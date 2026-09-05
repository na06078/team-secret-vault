// 암호.js — 브라우저 안에서 도는 모든 암호 연산 (WebCrypto API 사용, 외부 라이브러리 0개)
//
// 핵심 원칙: 마스터 비번과 평문 시크릿, 대칭키 원본은 절대 서버로 보내지 않는다.
// - 마스터 비번 → PBKDF2로 두 갈래(authKey: 로그인 증명 / vaultKey: 개인키 잠금용)
// - RSA-OAEP: 대칭키 봉인/해제 (공유의 핵심)
// - AES-GCM: 시크릿 본문 실제 암호화 (빠름·대용량)

const PBKDF2_ITER = 200000;

// ---------- base64 <-> ArrayBuffer 유틸 ----------
function bufToB64(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}
function b64ToBuf(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}
const enc = new TextEncoder();
const dec = new TextDecoder();

// ---------- 랜덤 salt 생성 ----------
function randomSaltB64() {
  return bufToB64(crypto.getRandomValues(new Uint8Array(16)));
}

// ---------- 마스터 비번 → 키 2갈래 ----------
// 반환: { authKey(base64 문자열, 서버로 감), vaultKey(CryptoKey, 로컬 전용) }
async function deriveKeys(password, saltB64) {
  const saltBytes = new Uint8Array(b64ToBuf(saltB64));
  const baseKey = await crypto.subtle.importKey(
    "raw", enc.encode(password), "PBKDF2", false, ["deriveBits", "deriveKey"]
  );

  // 컨텍스트를 salt 뒤에 붙여 서로 다른 키를 만든다.
  const authSalt = concatBytes(saltBytes, enc.encode("auth"));
  const vaultSalt = concatBytes(saltBytes, enc.encode("vault"));

  const authBits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: authSalt, iterations: PBKDF2_ITER, hash: "SHA-256" },
    baseKey, 256
  );

  const vaultKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: vaultSalt, iterations: PBKDF2_ITER, hash: "SHA-256" },
    baseKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
  );

  return { authKey: bufToB64(authBits), vaultKey };
}

function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0); out.set(b, a.length);
  return out;
}

// ---------- RSA 키쌍 생성 ----------
// 반환: { publicKeyB64(SPKI), privateKey(CryptoKey) }
async function generateRSAKeyPair() {
  const pair = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true, ["encrypt", "decrypt"]
  );
  const spki = await crypto.subtle.exportKey("spki", pair.publicKey);
  return { publicKeyB64: bufToB64(spki), privateKey: pair.privateKey };
}

// ---------- 개인키를 vaultKey로 잠그기/풀기 ----------
async function wrapPrivateKey(privateKey, vaultKey) {
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", privateKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encPriv = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, vaultKey, pkcs8);
  return { encPrivB64: bufToB64(encPriv), ivB64: bufToB64(iv) };
}
async function unwrapPrivateKey(encPrivB64, ivB64, vaultKey) {
  const iv = new Uint8Array(b64ToBuf(ivB64));
  const pkcs8 = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, vaultKey, b64ToBuf(encPrivB64));
  return crypto.subtle.importKey(
    "pkcs8", pkcs8, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["decrypt"]
  );
}

async function importPublicKey(publicKeyB64) {
  return crypto.subtle.importKey(
    "spki", b64ToBuf(publicKeyB64), { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"]
  );
}

// ---------- 시크릿 암호화 ----------
// 랜덤 대칭키 K 생성 → 본문 AES-GCM → K를 공개키로 봉인
// 반환: { ciphertextB64, ivB64, wrappedKeyB64 }
async function encryptSecret(plaintext, publicKeyB64) {
  const K = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, K, enc.encode(plaintext));

  const rawK = await crypto.subtle.exportKey("raw", K);
  const pub = await importPublicKey(publicKeyB64);
  const wrappedKey = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, pub, rawK);

  return { ciphertextB64: bufToB64(ciphertext), ivB64: bufToB64(iv), wrappedKeyB64: bufToB64(wrappedKey) };
}

// ---------- 시크릿 복호화 ----------
async function decryptSecret(ciphertextB64, ivB64, wrappedKeyB64, privateKey) {
  const rawK = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, b64ToBuf(wrappedKeyB64));
  const K = await crypto.subtle.importKey("raw", rawK, { name: "AES-GCM" }, false, ["decrypt"]);
  const iv = new Uint8Array(b64ToBuf(ivB64));
  const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, K, b64ToBuf(ciphertextB64));
  return dec.decode(plainBuf);
}

// ---------- 공유용 재봉인 ----------
// 내 개인키로 wrappedKey를 풀어 K 복원 → 대상 공개키로 다시 봉인
async function rewrapForUser(wrappedKeyB64, myPrivateKey, targetPublicKeyB64) {
  const rawK = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, myPrivateKey, b64ToBuf(wrappedKeyB64));
  const targetPub = await importPublicKey(targetPublicKeyB64);
  const rewrapped = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, targetPub, rawK);
  return bufToB64(rewrapped);
}

// ---------- 복구 키(Recovery Key) ----------
// Base32 알파벳(사람이 읽기 쉽게 헷갈리는 0/O/1/I 제외 — Crockford 계열)
const B32_ALPHABET = "ABCDEFGHJKMNPQRSTVWXYZ0123456789"; // 32자
function bytesToBase32(bytes) {
  let bits = 0, value = 0, out = "";
  for (const b of bytes) {
    value = (value << 8) | b; bits += 8;
    while (bits >= 5) { out += B32_ALPHABET[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}
function base32ToBytes(str) {
  const clean = str.toUpperCase().replace(/[^A-Z0-9]/g, "")
    .replace(/O/g, "0").replace(/I/g, "1").replace(/L/g, "1").replace(/U/g, "V");
  let bits = 0, value = 0; const out = [];
  for (const ch of clean) {
    const idx = B32_ALPHABET.indexOf(ch);
    if (idx < 0) continue;
    value = (value << 5) | idx; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return new Uint8Array(out);
}

// 복구 키 생성: 160비트(20B) 무작위 → Base32 32자 → 4자씩 8그룹 하이픈 연결
// 반환: { display: "XXXX-XXXX-...(8그룹)", keyBytes: Uint8Array(20) }
function generateRecoveryKey() {
  const keyBytes = crypto.getRandomValues(new Uint8Array(20));
  const b32 = bytesToBase32(keyBytes); // 32자
  const display = (b32.match(/.{1,4}/g) || []).join("-");
  return { display, keyBytes };
}

// 복구 키(표시 문자열 또는 바이트) → 2갈래 유도 (deriveKeys와 대칭)
// 반환: { recoveryAuthKey(base64), recoveryWrapKey(CryptoKey) }
async function deriveRecoveryKeys(recoveryKeyInput, recoverySaltB64) {
  const keyBytes = (recoveryKeyInput instanceof Uint8Array)
    ? recoveryKeyInput : base32ToBytes(String(recoveryKeyInput));
  const salt = new Uint8Array(b64ToBuf(recoverySaltB64));
  const baseKey = await crypto.subtle.importKey("raw", keyBytes, "PBKDF2", false, ["deriveBits", "deriveKey"]);
  const authBits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: concatBytes(salt, enc.encode("rec-auth")), iterations: PBKDF2_ITER, hash: "SHA-256" },
    baseKey, 256
  );
  const recoveryWrapKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: concatBytes(salt, enc.encode("rec-wrap")), iterations: PBKDF2_ITER, hash: "SHA-256" },
    baseKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
  );
  return { recoveryAuthKey: bufToB64(authBits), recoveryWrapKey };
}

window.암호 = {
  randomSaltB64, deriveKeys, generateRSAKeyPair,
  wrapPrivateKey, unwrapPrivateKey,
  encryptSecret, decryptSecret, rewrapForUser,
  generateRecoveryKey, deriveRecoveryKeys,
};
