// 공유·암호화 증거 테스트 — frontend/js/암호.js 와 동일한 WebCrypto 알고리즘으로 실제 서버 검증.
// 목적: (1) 서버로 나가는 데이터에 평문이 없음 (2) 공유가 실제로 됨 (3) 권한 없으면 복호화 실패
const BASE = "http://127.0.0.1:5000";
const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder(), dec = new TextDecoder();
const PBKDF2_ITER = 200000;
const bufToB64 = (b) => Buffer.from(new Uint8Array(b)).toString("base64");
const b64ToBuf = (s) => { const u = Buffer.from(s, "base64"); return u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength); };
function concatBytes(a, b) { const o = new Uint8Array(a.length + b.length); o.set(a, 0); o.set(b, a.length); return o; }

async function deriveKeys(password, saltB64) {
  const salt = new Uint8Array(b64ToBuf(saltB64));
  const base = await subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits", "deriveKey"]);
  const authBits = await subtle.deriveBits({ name: "PBKDF2", salt: concatBytes(salt, enc.encode("auth")), iterations: PBKDF2_ITER, hash: "SHA-256" }, base, 256);
  const vaultKey = await subtle.deriveKey({ name: "PBKDF2", salt: concatBytes(salt, enc.encode("vault")), iterations: PBKDF2_ITER, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  return { authKey: bufToB64(authBits), vaultKey };
}
async function genRSA() {
  const p = await subtle.generateKey({ name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: "SHA-256" }, true, ["encrypt","decrypt"]);
  return { publicKeyB64: bufToB64(await subtle.exportKey("spki", p.publicKey)), privateKey: p.privateKey };
}
async function wrapPriv(priv, vaultKey) {
  const pkcs8 = await subtle.exportKey("pkcs8", priv);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  return { encPrivB64: bufToB64(await subtle.encrypt({ name: "AES-GCM", iv }, vaultKey, pkcs8)), ivB64: bufToB64(iv) };
}
async function unwrapPriv(encB64, ivB64, vaultKey) {
  const iv = new Uint8Array(b64ToBuf(ivB64));
  const pkcs8 = await subtle.decrypt({ name: "AES-GCM", iv }, vaultKey, b64ToBuf(encB64));
  return subtle.importKey("pkcs8", pkcs8, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["decrypt"]);
}
const importPub = (b64) => subtle.importKey("spki", b64ToBuf(b64), { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"]);
async function encryptSecret(pt, pubB64) {
  const K = await subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt","decrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle.encrypt({ name: "AES-GCM", iv }, K, enc.encode(pt));
  const wrapped = await subtle.encrypt({ name: "RSA-OAEP" }, await importPub(pubB64), await subtle.exportKey("raw", K));
  return { ciphertextB64: bufToB64(ct), ivB64: bufToB64(iv), wrappedKeyB64: bufToB64(wrapped) };
}
async function decryptSecret(ctB64, ivB64, wkB64, priv) {
  const rawK = await subtle.decrypt({ name: "RSA-OAEP" }, priv, b64ToBuf(wkB64));
  const K = await subtle.importKey("raw", rawK, { name: "AES-GCM" }, false, ["decrypt"]);
  return dec.decode(await subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(b64ToBuf(ivB64)) }, K, b64ToBuf(ctB64)));
}
async function rewrap(wkB64, myPriv, targetPubB64) {
  const rawK = await subtle.decrypt({ name: "RSA-OAEP" }, myPriv, b64ToBuf(wkB64));
  return bufToB64(await subtle.encrypt({ name: "RSA-OAEP" }, await importPub(targetPubB64), rawK));
}

// 서버로 나가는 요청을 가로채서 기록하는 fetch (증거 수집용)
const 전송기록 = [];
function makeClient(라벨) {
  let cookie = "";
  return async (path, opts = {}) => {
    if (opts.body) 전송기록.push({ 누가: 라벨, 어디로: path, 보낸데이터: opts.body });
    const res = await fetch(BASE + path, { ...opts, headers: { "Content-Type": "application/json", ...(cookie ? { Cookie: cookie } : {}), ...(opts.headers||{}) } });
    const sc = res.headers.get("set-cookie"); if (sc) cookie = sc.split(";")[0];
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(`${path} → ${res.status}: ${data.error||""}`);
    return data;
  };
}
async function signup(client, username, password) {
  const salt = bufToB64(crypto.getRandomValues(new Uint8Array(16)));
  const { authKey, vaultKey } = await deriveKeys(password, salt);
  const { publicKeyB64, privateKey } = await genRSA();
  const { encPrivB64, ivB64 } = await wrapPriv(privateKey, vaultKey);
  await client("/api/register", { method: "POST", body: JSON.stringify({ username, salt, authKey, public_key: publicKeyB64, enc_priv: encPrivB64, enc_priv_iv: ivB64 }) });
}
async function login(client, username, password) {
  const { salt } = await client(`/api/salt?username=${username}`);
  const { authKey, vaultKey } = await deriveKeys(password, salt);
  const r = await client("/api/login", { method: "POST", body: JSON.stringify({ username, authKey }) });
  return await unwrapPriv(r.enc_priv, r.enc_priv_iv, vaultKey);
}

const line = "─".repeat(64);
(async () => {
  const A = makeClient("철수"), B = makeClient("영희"), C = makeClient("몰래"), stamp = Date.now();
  const 철수 = "철수_"+stamp, 영희 = "영희_"+stamp, 몰래 = "몰래_"+stamp;
  const 마스터비번_철수 = "cheolsu-pw-123";
  const 비밀값 = "sk-live-CEO급기밀-" + stamp;   // ← 이 평문이 서버/DB에 있으면 안 됨

  console.log(line); console.log("[준비] 사용자 3명 가입: 철수(소유자), 영희(공유대상), 몰래(권한없음)"); console.log(line);
  await signup(A, 철수, 마스터비번_철수);
  await signup(B, 영희, "younghee-pw-456");
  await signup(C, 몰래, "molae-pw-789");
  console.log("가입 완료\n");

  console.log(line); console.log("[증거 1] 철수가 시크릿을 저장할 때, 서버로 '실제로' 나가는 데이터"); console.log(line);
  console.log("원래 평문 시크릿 :", 비밀값);
  const 철수priv = await login(A, 철수, 마스터비번_철수);
  const 철수pub = (await A(`/api/users/${철수}/publickey`)).public_key;
  const e1 = await encryptSecret(비밀값, 철수pub);
  await A("/api/secrets", { method: "POST", body: JSON.stringify({ title: "회사 결제 API키", ciphertext: e1.ciphertextB64, iv: e1.ivB64, wrapped_key: e1.wrappedKeyB64 }) });
  const 저장요청 = 전송기록.find(r => r.어디로 === "/api/secrets");
  console.log("\n서버로 나간 실제 요청 본문(POST /api/secrets):");
  console.log(저장요청.보낸데이터.slice(0, 300) + " ...(생략)");
  const 평문포함 = 저장요청.보낸데이터.includes(비밀값);
  console.log(`\n→ 이 전송 데이터 안에 평문 '${비밀값}' 이 들어있나? : ${평문포함 ? "❌ 있음(문제!)" : "✅ 없음 — 암호문만 전송됨"}\n`);

  console.log(line); console.log("[증거 2] 마스터 비번도 서버로 안 나가는가?"); console.log(line);
  const 비번노출 = 전송기록.some(r => r.보낸데이터.includes(마스터비번_철수));
  console.log(`철수의 마스터 비번 '${마스터비번_철수}' 이 어떤 전송에도 들어있나? : ${비번노출 ? "❌ 있음(문제!)" : "✅ 없음 — 비번은 브라우저 밖으로 안 나감"}\n`);

  console.log(line); console.log("[증거 3] 공유가 진짜 되는가 — 영희가 자기 열쇠로 복호화"); console.log(line);
  const list철수 = await A("/api/secrets");
  const it = list철수[0];
  const 영희pub = (await A(`/api/users/${영희}/publickey`)).public_key;
  const wkForB = await rewrap(it.wrapped_key, 철수priv, 영희pub);
  await A(`/api/secrets/${it.id}/share`, { method: "POST", body: JSON.stringify({ target_username: 영희, wrapped_key: wkForB }) });
  console.log("철수 → 영희 공유 완료");
  const 영희priv = await login(B, 영희, "younghee-pw-456");
  const list영희 = await B("/api/secrets");
  const it2 = list영희.find(x => x.id === it.id);
  const dec영희 = await decryptSecret(it2.ciphertext, it2.iv, it2.wrapped_key, 영희priv);
  console.log("영희가 복호화한 값 :", dec영희);
  console.log(`→ 원본과 일치? : ${dec영희 === 비밀값 ? "✅ 일치 — 공유·복호화 성공" : "❌ 불일치"}\n`);

  console.log(line); console.log("[증거 4] 권한 없는 '몰래'는 접근/복호화가 막히는가"); console.log(line);
  const 몰래priv = await login(C, 몰래, "molae-pw-789");
  const list몰래 = await C("/api/secrets");
  console.log(`'몰래'의 시크릿 목록 개수 : ${list몰래.length} (공유 안 받았으므로 0이어야 함)`);
  // 설령 암호문을 훔쳐도 자기 개인키로는 못 푼다
  let 몰래결과;
  try { 몰래결과 = await decryptSecret(it.ciphertext, it.iv, it.wrapped_key, 몰래priv); 몰래결과 = "❌ 복호화됨(문제!): " + 몰래결과; }
  catch (e) { 몰래결과 = "✅ 복호화 실패 — 남의 열쇠로는 못 풂"; }
  console.log(`'몰래'가 철수의 암호문을 자기 개인키로 풀면? : ${몰래결과}\n`);

  console.log(line); console.log("[검증용] DB에서 찾을 평문 마커"); console.log(line);
  console.log("PLAINTEXT_MARKER:" + 비밀값);
  console.log("MASTERPW_MARKER:" + 마스터비번_철수);
})().catch(e => { console.error("에러:", e); process.exit(1); });
