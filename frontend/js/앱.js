// 앱.js — 화면 전환 + 이벤트. 개인키는 로그인 후 이 모듈 메모리에만 보관(새로고침 시 재로그인).
let 개인키 = null;      // CryptoKey (RSA private)
let 내공개키 = null;    // base64 SPKI (내 것)
let 현재사용자 = null;

const $ = (sel) => document.querySelector(sel);
const show = (id) => { $(id).classList.remove("hidden"); };
const hide = (id) => { $(id).classList.add("hidden"); };

function 알림(msg, isError = false) {
  const el = $("#알림");
  el.textContent = msg;
  el.className = isError ? "알림 오류" : "알림 성공";
  el.classList.remove("hidden");
  setTimeout(() => el.classList.add("hidden"), 4000);
}

// ---------- 회원가입 ----------
async function 회원가입(e) {
  e.preventDefault();
  const username = $("#가입-이름").value.trim();
  const password = $("#가입-비번").value;
  if (!username || !password) return 알림("이름과 비밀번호를 입력하세요.", true);

  try {
    const saltB64 = 암호.randomSaltB64();
    const { authKey, vaultKey } = await 암호.deriveKeys(password, saltB64);
    const { publicKeyB64, privateKey } = await 암호.generateRSAKeyPair();
    const { encPrivB64, ivB64 } = await 암호.wrapPrivateKey(privateKey, vaultKey);

    // 복구 키 발급 → 개인키를 복구 키로 한 벌 더 봉인
    const { display: 복구키표시, keyBytes } = 암호.generateRecoveryKey();
    const recoverySaltB64 = 암호.randomSaltB64();
    const { recoveryAuthKey, recoveryWrapKey } = await 암호.deriveRecoveryKeys(keyBytes, recoverySaltB64);
    const rec = await 암호.wrapPrivateKey(privateKey, recoveryWrapKey);

    await api.register({
      username, salt: saltB64, authKey,
      public_key: publicKeyB64, enc_priv: encPrivB64, enc_priv_iv: ivB64,
      recovery_salt: recoverySaltB64, recovery_auth_key: recoveryAuthKey,
      enc_priv_recovery: rec.encPrivB64, enc_priv_recovery_iv: rec.ivB64,
    });
    $("#가입-이름").value = ""; $("#가입-비번").value = "";
    복구키모달표시(복구키표시, "가입 완료! 아래 복구 키를 보관하세요.");
  } catch (err) {
    알림(err.message, true);
  }
}

// ---------- 로그인 ----------
async function 로그인(e) {
  e.preventDefault();
  const username = $("#로그인-이름").value.trim();
  const password = $("#로그인-비번").value;
  if (!username || !password) return 알림("이름과 비밀번호를 입력하세요.", true);

  try {
    const { salt } = await api.getSalt(username);
    const { authKey, vaultKey } = await 암호.deriveKeys(password, salt);
    const res = await api.login({ username, authKey });

    // 개인키를 vaultKey로 풀어 메모리에 보관
    개인키 = await 암호.unwrapPrivateKey(res.enc_priv, res.enc_priv_iv, vaultKey);
    const pk = await api.getPublicKey(username);
    내공개키 = pk.public_key;
    현재사용자 = username;

    await 금고화면으로();
  } catch (err) {
    알림(err.message, true);
  }
}

async function 금고화면으로() {
  hide("#인증화면"); show("#금고화면");
  $("#현재사용자").textContent = 현재사용자;
  await 목록새로고침();
}

// ---------- 로그아웃 ----------
async function 로그아웃() {
  try { await api.logout(); } catch (_) {}
  개인키 = null; 내공개키 = null; 현재사용자 = null;
  hide("#금고화면"); show("#인증화면");
}

// ---------- 시크릿 목록 ----------
async function 목록새로고침() {
  const 목록 = $("#시크릿목록");
  목록.innerHTML = "<li class='빈'>불러오는 중…</li>";
  try {
    const items = await api.listSecrets();
    if (items.length === 0) { 목록.innerHTML = "<li class='빈'>저장된 시크릿이 없습니다.</li>"; return; }
    목록.innerHTML = "";
    for (const it of items) {
      const li = document.createElement("li");
      li.className = "시크릿";
      li.innerHTML = `
        <div class="시크릿-머리">
          <span class="제목">🔒 ${escapeHtml(it.title)}</span>
          <span class="소유자">${it.is_owner ? "내 것" : "공유받음 · " + escapeHtml(it.owner_username)}</span>
        </div>
        <div class="값" data-id="${it.id}"></div>
        <div class="버튼줄">
          <button class="보기">보기</button>
          <button class="복사" disabled>복사</button>
          ${it.is_owner ? '<button class="공유">공유</button><button class="삭제">삭제</button>' : ""}
        </div>`;
      li._item = it;
      목록.appendChild(li);
    }
  } catch (err) {
    목록.innerHTML = `<li class='빈 오류'>${escapeHtml(err.message)}</li>`;
  }
}

// 목록 클릭 위임
function 목록클릭(e) {
  const li = e.target.closest("li.시크릿");
  if (!li) return;
  const it = li._item;
  if (e.target.classList.contains("보기")) 보기(li, it);
  else if (e.target.classList.contains("복사")) 복사(li);
  else if (e.target.classList.contains("공유")) 공유(it);
  else if (e.target.classList.contains("삭제")) 삭제(it);
}

async function 보기(li, it) {
  const 값칸 = li.querySelector(".값");
  try {
    const 평문 = await 암호.decryptSecret(it.ciphertext, it.iv, it.wrapped_key, 개인키);
    값칸.textContent = 평문;
    값칸.dataset.plain = 평문;
    li.querySelector(".복사").disabled = false;
    li.querySelector(".제목").textContent = "🔓 " + it.title;
  } catch (err) {
    값칸.textContent = "복호화 실패: " + err.message;
    값칸.classList.add("오류");
  }
}

async function 복사(li) {
  const 평문 = li.querySelector(".값").dataset.plain;
  if (평문 != null) { await navigator.clipboard.writeText(평문); 알림("클립보드에 복사했습니다."); }
}

async function 삭제(it) {
  if (!confirm(`'${it.title}'를 삭제할까요? 공유받은 사람의 접근도 함께 사라집니다.`)) return;
  try { await api.deleteSecret(it.id); 알림("삭제했습니다."); await 목록새로고침(); }
  catch (err) { 알림(err.message, true); }
}

async function 공유(it) {
  const target = prompt(`'${it.title}'를 공유할 사용자명을 입력하세요:`);
  if (!target) return;
  try {
    const pk = await api.getPublicKey(target.trim());
    const wrapped = await 암호.rewrapForUser(it.wrapped_key, 개인키, pk.public_key);
    await api.share(it.id, { target_username: target.trim(), wrapped_key: wrapped });
    알림(`${target}에게 공유했습니다.`);
  } catch (err) {
    알림(err.message, true);
  }
}

// ---------- 새 시크릿 추가 ----------
async function 시크릿추가(e) {
  e.preventDefault();
  const title = $("#새-제목").value.trim();
  const body = $("#새-내용").value;
  if (!title || !body) return 알림("제목과 내용을 입력하세요.", true);
  try {
    const { ciphertextB64, ivB64, wrappedKeyB64 } = await 암호.encryptSecret(body, 내공개키);
    await api.createSecret({ title, ciphertext: ciphertextB64, iv: ivB64, wrapped_key: wrappedKeyB64 });
    $("#새-제목").value = ""; $("#새-내용").value = "";
    알림("저장했습니다.");
    await 목록새로고침();
  } catch (err) {
    알림(err.message, true);
  }
}

// ---------- 복구 키 모달 ----------
function 복구키모달표시(복구키, 안내메시지) {
  $("#복구키값").textContent = 복구키;
  $("#복구키확인").checked = false;
  $("#복구키닫기").disabled = true;
  $("#복구키모달").classList.remove("hidden");
  if (안내메시지) 알림(안내메시지);
}

// ---------- 계정 복구(비번 재설정) ----------
async function 복구실행(e) {
  e.preventDefault();
  const username = $("#복구-이름").value.trim();
  const 복구키 = $("#복구-키").value.trim();
  const 새비번 = $("#복구-새비번").value;
  if (!username || !복구키 || !새비번) return 알림("모든 칸을 입력하세요.", true);

  try {
    // 1) 복구용 salt → 복구 키 2갈래 유도
    const { recovery_salt } = await api.getRecoverySalt(username);
    const { recoveryAuthKey, recoveryWrapKey } = await 암호.deriveRecoveryKeys(복구키, recovery_salt);

    // 2) 검증 통과 시 개인키 복구 사본(암호문) 수령 → 복호화
    const { enc_priv_recovery, enc_priv_recovery_iv } =
      await api.getRecoveryPriv({ username, recovery_auth_key: recoveryAuthKey });
    const privateKey = await 암호.unwrapPrivateKey(enc_priv_recovery, enc_priv_recovery_iv, recoveryWrapKey);

    // 3) 새 비번으로 개인키 재봉인 → 서버 갱신
    const newSalt = 암호.randomSaltB64();
    const { authKey: newAuthKey, vaultKey: newVaultKey } = await 암호.deriveKeys(새비번, newSalt);
    const { encPrivB64, ivB64 } = await 암호.wrapPrivateKey(privateKey, newVaultKey);
    await api.recover({
      username, recovery_auth_key: recoveryAuthKey,
      new_salt: newSalt, new_auth_key: newAuthKey,
      new_enc_priv: encPrivB64, new_enc_priv_iv: ivB64,
    });

    $("#복구-이름").value = ""; $("#복구-키").value = ""; $("#복구-새비번").value = "";
    hide("#복구화면"); show("#인증화면");
    알림("복구 완료! 새 비밀번호로 로그인하세요.");
  } catch (err) {
    알림("복구 실패: " + err.message, true);
  }
}

// ---------- 복구 키 재발급 (로그인 상태) ----------
async function 복구키재발급() {
  if (!개인키) return 알림("로그인 상태가 아닙니다.", true);
  if (!confirm("새 복구 키를 발급하면 이전 복구 키는 무효화됩니다. 계속할까요?")) return;
  try {
    const { display: 복구키표시, keyBytes } = 암호.generateRecoveryKey();
    const recoverySaltB64 = 암호.randomSaltB64();
    const { recoveryAuthKey, recoveryWrapKey } = await 암호.deriveRecoveryKeys(keyBytes, recoverySaltB64);
    const rec = await 암호.wrapPrivateKey(개인키, recoveryWrapKey);
    await api.resetRecoveryKey({
      recovery_salt: recoverySaltB64, recovery_auth_key: recoveryAuthKey,
      enc_priv_recovery: rec.encPrivB64, enc_priv_recovery_iv: rec.ivB64,
    });
    복구키모달표시(복구키표시, "새 복구 키가 발급되었습니다.");
  } catch (err) {
    알림(err.message, true);
  }
}

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// ---------- 초기화 ----------
document.addEventListener("DOMContentLoaded", () => {
  $("#가입폼").addEventListener("submit", 회원가입);
  $("#로그인폼").addEventListener("submit", 로그인);
  $("#로그아웃").addEventListener("click", 로그아웃);
  $("#추가폼").addEventListener("submit", 시크릿추가);
  $("#시크릿목록").addEventListener("click", 목록클릭);

  // 복구 키 관련
  $("#복구링크").addEventListener("click", (e) => { e.preventDefault(); hide("#인증화면"); show("#복구화면"); });
  $("#복구취소").addEventListener("click", (e) => { e.preventDefault(); hide("#복구화면"); show("#인증화면"); });
  $("#복구폼").addEventListener("submit", 복구실행);
  $("#복구키재발급").addEventListener("click", 복구키재발급);
  $("#복구키확인").addEventListener("change", (e) => { $("#복구키닫기").disabled = !e.target.checked; });
  $("#복구키닫기").addEventListener("click", () => { $("#복구키모달").classList.add("hidden"); });
  $("#복구키복사").addEventListener("click", async () => {
    await navigator.clipboard.writeText($("#복구키값").textContent);
    알림("복구 키를 복사했습니다.");
  });

  if (!window.crypto || !window.crypto.subtle) {
    알림("이 브라우저는 WebCrypto를 지원하지 않거나 보안 컨텍스트(localhost/https)가 아닙니다.", true);
  }
});
