CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT UNIQUE NOT NULL,
    salt        TEXT NOT NULL,          -- base64, KDF용(클라이언트 생성)
    auth_hash   TEXT NOT NULL,          -- bcrypt(authKey). 서버 저장용
    public_key  TEXT NOT NULL,          -- base64 SPKI, RSA 공개키
    enc_priv    TEXT NOT NULL,          -- base64, vaultKey로 암호화된 개인키
    enc_priv_iv TEXT NOT NULL,          -- base64, 개인키 암호화 IV
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS secrets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id    INTEGER NOT NULL REFERENCES users(id),
    title       TEXT NOT NULL,          -- 평문 라벨(검색용, 민감정보 넣지 말 것)
    ciphertext  TEXT NOT NULL,          -- base64, AES-GCM 암호문
    iv          TEXT NOT NULL,          -- base64, AES-GCM IV
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS shares (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    secret_id     INTEGER NOT NULL REFERENCES secrets(id),
    user_id       INTEGER NOT NULL REFERENCES users(id),  -- 접근 권한자(소유자 포함)
    wrapped_key   TEXT NOT NULL,        -- base64, 해당 user 공개키로 봉인한 대칭키 K
    created_at    TEXT NOT NULL,
    UNIQUE(secret_id, user_id)
);
