// 복구 키 증거 테스트 — frontend/js/암호.js 와 동일 알고리즘으로 실제 서버 검증.
// 시나리오: 가입(복구키 수령) → 시크릿 저장 → "비번 분실" → 복구키로 새 비번 설정 → 새 비번 로그인 → 복호화
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
// 복구 키: 20B → Base32(0/O,1/I 제외) → 4자 8그룹
const B32 = "ABCDEFGHJKMNPQRSTVWXYZ0123456789";
function bytesToBase32(bytes) { let bits=0,value=0,out=""; for(const b of bytes){value=(value<<8)|b;bits+=8;while(bits>=5){out+=B32[(value>>>(bits-5))&31];bits-=5;}} if(bits>0)out+=B32[(value<<(5-bits))&31]; return out; }
function base32ToBytes(str){const clean=str.toUpperCase().replace(/[^A-Z0-9]/g,"").replace(/O/g,"0").replace(/I/g,"1").replace(/L/g,"1").replace(/U/g,"V");let bits=0,value=0;const out=[];for(const ch of clean){const i=B32.indexOf(ch);if(i<0)continue;value=(value<<5)|i;bits+=5;if(bits>=8){out.push((value>>>(bits-8))&0xff);bits-=8;}}return new Uint8Array(out);}
function generateRecoveryKey(){const keyBytes=crypto.getRandomValues(new Uint8Array(20));const b=bytesToBase32(keyBytes);return{display:(b.match(/.{1,4}/g)||[]).join("-"),keyBytes};}
async function deriveRecoveryKeys(input, saltB64){
  const keyBytes=(input instanceof Uint8Array)?input:base32ToBytes(String(input));
  const salt=new Uint8Array(b64ToBuf(saltB64));
  const base=await subtle.importKey("raw",keyBytes,"PBKDF2",false,["deriveBits","deriveKey"]);
  const authBits=await subtle.deriveBits({name:"PBKDF2",salt:concatBytes(salt,enc.encode("rec-auth")),iterations:PBKDF2_ITER,hash:"SHA-256"},base,256);
  const recoveryWrapKey=await subtle.deriveKey({name:"PBKDF2",salt:concatBytes(salt,enc.encode("rec-wrap")),iterations:PBKDF2_ITER,hash:"SHA-256"},base,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
  return { recoveryAuthKey: bufToB64(authBits), recoveryWrapKey };
}
async function genRSA(){const p=await subtle.generateKey({name:"RSA-OAEP",modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:"SHA-256"},true,["encrypt","decrypt"]);return{publicKeyB64:bufToB64(await subtle.exportKey("spki",p.publicKey)),privateKey:p.privateKey};}
async function wrapPriv(priv,key){const pkcs8=await subtle.exportKey("pkcs8",priv);const iv=crypto.getRandomValues(new Uint8Array(12));return{encPrivB64:bufToB64(await subtle.encrypt({name:"AES-GCM",iv},key,pkcs8)),ivB64:bufToB64(iv)};}
async function unwrapPriv(encB64,ivB64,key){const iv=new Uint8Array(b64ToBuf(ivB64));const pkcs8=await subtle.decrypt({name:"AES-GCM",iv},key,b64ToBuf(encB64));return subtle.importKey("pkcs8",pkcs8,{name:"RSA-OAEP",hash:"SHA-256"},true,["decrypt"]);}
const importPub=(b64)=>subtle.importKey("spki",b64ToBuf(b64),{name:"RSA-OAEP",hash:"SHA-256"},true,["encrypt"]);
async function encryptSecret(pt,pubB64){const K=await subtle.generateKey({name:"AES-GCM",length:256},true,["encrypt","decrypt"]);const iv=crypto.getRandomValues(new Uint8Array(12));const ct=await subtle.encrypt({name:"AES-GCM",iv},K,enc.encode(pt));const w=await subtle.encrypt({name:"RSA-OAEP"},await importPub(pubB64),await subtle.exportKey("raw",K));return{ciphertextB64:bufToB64(ct),ivB64:bufToB64(iv),wrappedKeyB64:bufToB64(w)};}
async function decryptSecret(ctB64,ivB64,wkB64,priv){const rawK=await subtle.decrypt({name:"RSA-OAEP"},priv,b64ToBuf(wkB64));const K=await subtle.importKey("raw",rawK,{name:"AES-GCM"},false,["decrypt"]);return dec.decode(await subtle.decrypt({name:"AES-GCM",iv:new Uint8Array(b64ToBuf(ivB64))},K,b64ToBuf(ctB64)));}

function makeClient(){let cookie="";return async(path,opts={})=>{const res=await fetch(BASE+path,{...opts,headers:{"Content-Type":"application/json",...(cookie?{Cookie:cookie}:{}),...(opts.headers||{})}});const sc=res.headers.get("set-cookie");if(sc)cookie=sc.split(";")[0];const data=await res.json().catch(()=>({}));if(!res.ok)throw new Error(`${path} → ${res.status}: ${data.error||""}`);return data;};}

const line="─".repeat(64);
(async()=>{
  const A=makeClient(), stamp=Date.now();
  const user="복구테스트_"+stamp, oldPw="old-master-pw", newPw="new-master-pw-CHANGED";
  const 비밀값="db-password-복구후에도열려야함-"+stamp;

  console.log(line); console.log("[1] 가입 + 복구 키 발급"); console.log(line);
  const salt=randomSalt(); const {authKey,vaultKey}=await deriveKeys(oldPw,salt);
  const {publicKeyB64,privateKey}=await genRSA();
  const ep=await wrapPriv(privateKey,vaultKey);
  const {display:복구키, keyBytes}=generateRecoveryKey();
  const recSalt=randomSalt(); const {recoveryAuthKey,recoveryWrapKey}=await deriveRecoveryKeys(keyBytes,recSalt);
  const epr=await wrapPriv(privateKey,recoveryWrapKey);
  await A("/api/register",{method:"POST",body:JSON.stringify({username:user,salt,authKey,public_key:publicKeyB64,enc_priv:ep.encPrivB64,enc_priv_iv:ep.ivB64,recovery_salt:recSalt,recovery_auth_key:recoveryAuthKey,enc_priv_recovery:epr.encPrivB64,enc_priv_recovery_iv:epr.ivB64})});
  console.log("발급된 복구 키:", 복구키, "\n");

  console.log(line); console.log("[2] 로그인 + 시크릿 저장 (원래 비번)"); console.log(line);
  await login(A,user,oldPw);
  const pub=(await A(`/api/users/${user}/publickey`)).public_key;
  const e1=await encryptSecret(비밀값,pub);
  await A("/api/secrets",{method:"POST",body:JSON.stringify({title:"운영 DB 비번",ciphertext:e1.ciphertextB64,iv:e1.ivB64,wrapped_key:e1.wrappedKeyB64})});
  console.log("시크릿 저장 완료\n");

  console.log(line); console.log("[3] 💥 마스터 비번 분실 가정 → 복구 키로 새 비번 설정"); console.log(line);
  const B=makeClient(); // 새 세션(비번 모름)
  const {recovery_salt}=await B(`/api/recovery-salt?username=${user}`);
  const rk=await deriveRecoveryKeys(복구키, recovery_salt); // 표시 문자열로 유도(왕복 검증)
  const {enc_priv_recovery,enc_priv_recovery_iv}=await B("/api/recovery-priv",{method:"POST",body:JSON.stringify({username:user,recovery_auth_key:rk.recoveryAuthKey})});
  const recoveredPriv=await unwrapPriv(enc_priv_recovery,enc_priv_recovery_iv,rk.recoveryWrapKey);
  const newSalt=randomSalt(); const nk=await deriveKeys(newPw,newSalt);
  const nep=await wrapPriv(recoveredPriv,nk.vaultKey);
  await B("/api/recover",{method:"POST",body:JSON.stringify({username:user,recovery_auth_key:rk.recoveryAuthKey,new_salt:newSalt,new_auth_key:nk.authKey,new_enc_priv:nep.encPrivB64,new_enc_priv_iv:nep.ivB64})});
  console.log("복구 키로 새 비번 설정 완료\n");

  console.log(line); console.log("[4] 새 비번으로 로그인 + 기존 시크릿 복호화"); console.log(line);
  const C=makeClient();
  const cPriv=await login(C,user,newPw);
  const list=await C("/api/secrets");
  const dec1=await decryptSecret(list[0].ciphertext,list[0].iv,list[0].wrapped_key,cPriv);
  console.log("복호화 값:",dec1);
  console.log(`→ 원본과 일치? : ${dec1===비밀값?"✅ 일치 — 복구 성공, 기존 시크릿 그대로 열림":"❌ 불일치"}\n`);

  console.log(line); console.log("[5] 옛 비번은 이제 안 되는가"); console.log(line);
  try{ await login(makeClient(),user,oldPw); console.log("❌ 옛 비번으로 로그인됨(문제!)"); }
  catch(e){ console.log("✅ 옛 비번 거부됨:",e.message); }

  console.log("\n"+line); console.log("[6] 틀린 복구 키는 막히는가"); console.log(line);
  const {recovery_salt:rs2}=await makeClient()(`/api/recovery-salt?username=${user}`);
  const badRk=await deriveRecoveryKeys("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH", rs2);
  try{ await makeClient()("/api/recovery-priv",{method:"POST",body:JSON.stringify({username:user,recovery_auth_key:badRk.recoveryAuthKey})}); console.log("❌ 틀린 복구키 통과됨(문제!)"); }
  catch(e){ console.log("✅ 틀린 복구키 거부됨:",e.message); }

  console.log("\nPLAINTEXT_MARKER:"+비밀값);
  console.log("RECOVERYKEY_MARKER:"+복구키);
})().catch(e=>{console.error("에러:",e);process.exit(1);});

function randomSalt(){return bufToB64(crypto.getRandomValues(new Uint8Array(16)));}
async function login(client,username,password){const {salt}=await client(`/api/salt?username=${username}`);const {authKey,vaultKey}=await deriveKeys(password,salt);const r=await client("/api/login",{method:"POST",body:JSON.stringify({username,authKey})});return await unwrapPriv(r.enc_priv,r.enc_priv_iv,vaultKey);}
