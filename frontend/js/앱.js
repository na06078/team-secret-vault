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

    await api.register({
      username, salt: saltB64, authKey,
      public_key: publicKeyB64, enc_priv: encPrivB64, enc_priv_iv: ivB64,
    });
    알림("가입 완료! 이제 로그인하세요.");
    $("#가입-이름").value = ""; $("#가입-비번").value = "";
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

  if (!window.crypto || !window.crypto.subtle) {
    알림("이 브라우저는 WebCrypto를 지원하지 않거나 보안 컨텍스트(localhost/https)가 아닙니다.", true);
  }
});
