// api.js — 백엔드 /api/* 호출 래퍼. 세션 쿠키는 브라우저가 자동 전송.
async function jsonFetch(url, options = {}) {
  const res = await fetch(url, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.error || `요청 실패 (${res.status})`);
  }
  return data;
}

window.api = {
  register: (body) => jsonFetch("/api/register", { method: "POST", body: JSON.stringify(body) }),
  getSalt: (username) => jsonFetch(`/api/salt?username=${encodeURIComponent(username)}`),
  login: (body) => jsonFetch("/api/login", { method: "POST", body: JSON.stringify(body) }),
  logout: () => jsonFetch("/api/logout", { method: "POST" }),
  me: () => jsonFetch("/api/me"),
  listSecrets: () => jsonFetch("/api/secrets"),
  createSecret: (body) => jsonFetch("/api/secrets", { method: "POST", body: JSON.stringify(body) }),
  deleteSecret: (id) => jsonFetch(`/api/secrets/${id}`, { method: "DELETE" }),
  getPublicKey: (username) => jsonFetch(`/api/users/${encodeURIComponent(username)}/publickey`),
  share: (id, body) => jsonFetch(`/api/secrets/${id}/share`, { method: "POST", body: JSON.stringify(body) }),
  // 복구 키
  getRecoverySalt: (username) => jsonFetch(`/api/recovery-salt?username=${encodeURIComponent(username)}`),
  getRecoveryPriv: (body) => jsonFetch("/api/recovery-priv", { method: "POST", body: JSON.stringify(body) }),
  recover: (body) => jsonFetch("/api/recover", { method: "POST", body: JSON.stringify(body) }),
  resetRecoveryKey: (body) => jsonFetch("/api/recovery-key/reset", { method: "POST", body: JSON.stringify(body) }),
};
