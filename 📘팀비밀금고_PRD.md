# 📘 팀 비밀 금고 (제로지식 시크릿 볼트) — 개발 명세서(PRD)

> **작성 목적**: 이 문서만 읽고도 개발 의도·구조·보안 모델·인터페이스 계약을 정확히 파악해 구현할 수 있게 하는 명세서입니다.
> **상태**: 설계 단계. 코드·설치 없음. (2026-09-05 작성)
> **실습 성격**: 아이펠 학습 실습 — 백엔드/프론트엔드 분리, 해시/솔트, 공개키, 세션키(대칭키)를 억지 없이 한 흐름에서 사용.

---

## 1. 프로젝트 개요

### 1.1 목적
- **해결하는 문제**: API 키·DB 비밀번호·토큰 같은 민감 정보를 팀원끼리 카톡/메일/슬랙으로 주고받는 관행은 위험하다(대화 기록·서버·백업에 평문으로 남음).
- **목표**: 시크릿을 안전하게 보관하고, 특정 팀원에게만 공유하되, **서버 운영자(=나)조차 평문을 절대 볼 수 없는** 제로지식(Zero-Knowledge) 금고를 만든다.
- **핵심 가치 명제**: "서버가 털려도, 개발자가 악의를 품어도, 평문 시크릿과 마스터 비밀번호는 어디에도 없다."

### 1.2 기술 스택
- **백엔드**: Python 3.11 + Flask, SQLite(표준 라이브러리 `sqlite3`), `bcrypt`(인증 해시 저장).
- **프론트엔드**: 순수 HTML/CSS/JS(빌드 스텝 없음). 암호 연산은 브라우저 내장 **WebCrypto API**(외부 JS 라이브러리 0개).
- **암호 알고리즘**:
  - KDF(키 유도): **PBKDF2-HMAC-SHA256** (마스터 비번 → 키 2갈래).
  - 대칭 암호(세션키): **AES-GCM 256bit** (시크릿 본문 암호화).
  - 공개키 암호: **RSA-OAEP 2048bit** (대칭키 봉인 → 공유).
  - 인증 해시 저장: **bcrypt** (서버가 받은 인증값을 한 번 더 해시+솔트).
- **통신**: 백엔드는 `/api/*` JSON만, 프론트 정적 파일은 Flask가 같은 오리진에서 서빙(CORS 회피, 서버 1개로 실습 단순화).

### 1.3 제약사항 및 비목표 (Critical ⚠️)
- **비밀번호 복구 없음**: 마스터 비번을 잊으면 금고 복구 불가(제로지식의 본질적 결과). README에 명시.
- **키 회전/폐기(revocation) 없음(v1)**: 이미 공유한 시크릿을 나중에 회수하는 기능은 v1 제외.
- **실시간·알림·모바일 앱 없음**: 웹 화면만.
- **HTTPS는 실습 범위 밖**: 로컬 `http://127.0.0.1`에서만 실행. WebCrypto는 `localhost`/`127.0.0.1`을 보안 컨텍스트로 인정하므로 동작함. **공개 배포는 v1 비목표**(배포하려면 HTTPS 필수 — README 경고).
- **비밀번호 강도 검사·2FA·이메일 인증 없음(v1)**: 사용자명+마스터 비번만.
- **관리자/권한 등급 없음**: 모든 사용자는 동등. 팀=시크릿을 서로 공유할 수 있는 사용자 집합(암묵적).

---

## 2. 보안 모델 (이 프로젝트의 심장)

> 배운 4개 개념이 여기서 톱니처럼 맞물린다. 구현 시 이 절을 최우선 계약으로 삼는다.

### 2.1 회원가입 시 (전부 브라우저에서 계산)
1. 사용자가 마스터 비번 `P` 입력.
2. 클라이언트가 랜덤 `salt`(16B) 생성.
3. `P`+`salt`로 **PBKDF2를 2번 서로 다른 정보(info)로 유도** → 키 2갈래:
   - **인증키 `authKey`**: 서버로 보내는 로그인 증명값. (서버는 이걸 다시 bcrypt로 해시해 저장 → 서버는 `P`도 `authKey` 원본도 안전하게만 취급)
   - **볼트키 `vaultKey`**: **절대 서버로 안 감.** 내 RSA 개인키를 잠그는 대칭키.
4. 클라이언트가 **RSA 키쌍** 생성:
   - 공개키 `pub`: 평문 그대로 서버에 저장(남이 나에게 봉인할 때 씀).
   - 개인키 `priv`: `vaultKey`로 AES-GCM 암호화 → `encPriv`만 서버에 저장. (어느 기기서 로그인해도 마스터 비번으로 풀 수 있게)
5. 서버로 전송: `username, salt, authKey, pub, encPriv`. → 서버는 `authKey`를 bcrypt 해시해 저장.

### 2.2 로그인 시
1. 서버에서 `username`의 `salt`를 받아옴.
2. 클라이언트가 `P`+`salt`로 `authKey`·`vaultKey` 재유도.
3. `authKey`를 서버로 전송 → 서버가 bcrypt로 대조 → 성공 시 **세션 토큰(쿠키)** 발급.
4. 서버가 `encPriv` 반환 → 클라이언트가 `vaultKey`로 복호화해 **개인키를 메모리에만** 보유(세션 동안).

### 2.3 시크릿 저장 시
1. 클라이언트가 랜덤 **대칭키(=세션키) `K`**(AES-256) 생성.
2. 시크릿 본문을 `K`로 AES-GCM 암호화 → `ciphertext`, `iv`.
3. `K`를 **내 공개키 `pub`로 RSA-OAEP 봉인** → `wrappedKey_me`.
4. 서버로 전송: `title(평문 라벨), ciphertext, iv, wrappedKey_me`. **서버는 `K`도 평문도 모름.**

### 2.4 팀원 공유 시
1. 공유 대상의 공개키 `pub_other`를 서버에서 조회.
2. 원 소유자가 자기 개인키로 `wrappedKey_me`를 풀어 `K` 복원 → `K`를 `pub_other`로 다시 봉인 → `wrappedKey_other`.
3. 서버에 `(secret_id, 대상 user, wrappedKey_other)` 공유 레코드 저장. → 대상은 로그인 후 자기 개인키로 `K`를 풀어 복호화.

### 2.5 개념 매핑 요약
| 배운 개념 | 이 서비스에서 하는 일 |
|---|---|
| 해시/솔트 | 서버가 `authKey`를 bcrypt(솔트 자동)로 저장 → DB 유출돼도 비번 복원 불가 |
| 공개키/개인키 | 대칭키 봉인·공유. 서버는 공개키·암호문만 봄 |
| 세션키(대칭키) | 시크릿 본문을 AES-GCM으로 실제 암호화(빠름·대용량) |
| 세션 토큰 | 로그인 유지(쿠키). 매 요청 비번 재전송 방지 |
| 백엔드/프론트엔드 | 프론트=모든 암호 연산, 백=암호문·해시·세션만 |

### 2.6 위협 모델 (무엇을 막고, 무엇을 못 막나)
- ✅ **막음**: DB 통째 유출, 악의적 서버 운영자, 네트워크 도청(암호문만 흐름).
- ❌ **못 막음(설계상 범위 밖)**: 사용자 브라우저 자체가 감염(개인키 메모리 탈취), 피싱, 마스터 비번 분실 시 복구, 취약 마스터 비번 무차별 대입(v1은 강도 검사 없음).

---

## 3. 데이터 모델

### 3.1 핵심 엔티티
- **users**: 사용자 계정과 공개 자료.
- **secrets**: 암호화된 시크릿 본문(소유자 것).
- **shares**: 특정 사용자에게 봉인된 시크릿 접근 키.
- **sessions**: (Flask 서버측 세션 사용 시 생략 가능. 쿠키 서명 세션이면 테이블 불필요.)

### 3.2 스키마 (DDL)
```sql
CREATE TABLE users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT UNIQUE NOT NULL,
    salt        TEXT NOT NULL,          -- base64, KDF용(클라이언트 생성)
    auth_hash   TEXT NOT NULL,          -- bcrypt(authKey). 서버 저장용
    public_key  TEXT NOT NULL,          -- base64 SPKI, RSA 공개키
    enc_priv    TEXT NOT NULL,          -- base64, vaultKey로 암호화된 개인키
    enc_priv_iv TEXT NOT NULL,          -- base64, 개인키 암호화 IV
    created_at  TEXT NOT NULL
);

CREATE TABLE secrets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id    INTEGER NOT NULL REFERENCES users(id),
    title       TEXT NOT NULL,          -- 평문 라벨(검색용, 민감정보 넣지 말 것)
    ciphertext  TEXT NOT NULL,          -- base64, AES-GCM 암호문
    iv          TEXT NOT NULL,          -- base64, AES-GCM IV
    created_at  TEXT NOT NULL
);

CREATE TABLE shares (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    secret_id     INTEGER NOT NULL REFERENCES secrets(id),
    user_id       INTEGER NOT NULL REFERENCES users(id),  -- 접근 권한자(소유자 포함)
    wrapped_key   TEXT NOT NULL,        -- base64, 해당 user 공개키로 봉인한 대칭키 K
    created_at    TEXT NOT NULL,
    UNIQUE(secret_id, user_id)
);
```
- **원칙**: `secrets.title` 외에는 평문이 DB에 절대 없음. `owner` 본인도 `shares`에 자기 wrapped_key 레코드를 가진다(저장 시 자동 생성).

---

## 4. 기능 명세 (API 계약)

> 모든 `/api/*`는 JSON. 인증 필요한 엔드포인트는 세션 쿠키 확인.

### 4.1 회원가입
- **API**: `POST /api/register`
- **입력**: `{ username, salt, authKey, public_key, enc_priv, enc_priv_iv }`
- **처리**: username 중복 확인 → `auth_hash = bcrypt(authKey)` → users insert.
- **출력**: `201 { ok: true }`
- **에러**: username 존재 시 `409`, 필드 누락 `400`.

### 4.2 로그인 준비(솔트 조회)
- **API**: `GET /api/salt?username=...`
- **출력**: `{ salt }`
- **⚠️ 실습 단순화 결정**: 없는 사용자면 `404`. 즉 이 엔드포인트로 **사용자명 존재 여부가 노출된다**(실습이므로 감수). 실서비스라면 더미 솔트 반환 또는 사용자명 기반 결정론적 salt 유도로 막아야 함.

### 4.3 로그인
- **API**: `POST /api/login`
- **입력**: `{ username, authKey }`
- **처리**: `bcrypt.verify(authKey, auth_hash)` → 성공 시 세션 쿠키 발급.
- **출력**: `{ ok: true, enc_priv, enc_priv_iv }` (클라이언트가 vaultKey로 개인키 복호화)
- **에러**: 불일치 `401`.

### 4.4 로그아웃
- **API**: `POST /api/logout` → 세션 삭제 → `{ ok: true }`

### 4.5 내 시크릿 목록
- **API**: `GET /api/secrets` (인증 필요)
- **처리**: 내가 접근 가능한(shares에 내 레코드가 있는) 시크릿 조인 조회.
- **출력**: `[{ id, title, ciphertext, iv, wrapped_key, owner_username }]`

### 4.6 시크릿 생성
- **API**: `POST /api/secrets` (인증 필요)
- **입력**: `{ title, ciphertext, iv, wrapped_key }` (wrapped_key = 내 공개키로 봉인)
- **처리**: secrets insert + shares(owner 본인) insert (트랜잭션).
- **출력**: `201 { id }`
- **에러**: title 빈값 `400`.

### 4.7 사용자 공개키 조회(공유 대상 찾기)
- **API**: `GET /api/users/<username>/publickey` (인증 필요)
- **출력**: `{ username, public_key }` / 없으면 `404`.

### 4.8 시크릿 공유
- **API**: `POST /api/secrets/<id>/share` (인증 필요, 소유자만)
- **입력**: `{ target_username, wrapped_key }` (대상 공개키로 봉인한 K)
- **처리**: 요청자가 소유자인지 확인 → shares insert(대상 user).
- **출력**: `201 { ok: true }`
- **에러**: 소유자 아님 `403`, 대상 없음 `404`, 이미 공유됨 `409`.

### 4.9 시크릿 삭제
- **API**: `DELETE /api/secrets/<id>` (소유자만)
- **처리**: 요청자가 소유자인지 확인 → 해당 secret과 **관련 shares 전부 삭제**(트랜잭션). 즉 **공유받은 팀원의 접근도 함께 사라진다**(실습 단순화 결정).
- **출력**: `{ ok: true }` / 소유자 아님 `403`.
- **비고**: 공유받은 사람이 스스로 "내 접근만 제거"하는 기능은 v1 제외.

---

## 5. 아키텍처 및 의존도

### 5.1 디렉토리/파일 구조
```text
팀비밀금고/
├─ backend/
│  ├─ app.py              # Flask 진입점: 정적 서빙 + 블루프린트 등록 + 세션 설정
│  ├─ config.py           # SECRET_KEY 등 .env 로드
│  ├─ db.py               # sqlite3 연결·초기화(schema.sql 실행)
│  ├─ schema.sql          # 테이블 DDL (2.x)
│  ├─ routes/
│  │  ├─ 인증.py          # register/salt/login/logout
│  │  ├─ 시크릿.py        # secrets CRUD
│  │  └─ 공유.py          # publickey 조회, share
│  ├─ requirements.txt    # flask, bcrypt, python-dotenv
│  └─ instance/          # 금고.db 생성 위치 (gitignore)
├─ frontend/
│  ├─ index.html          # 로그인/회원가입 화면
│  ├─ 금고.html           # 시크릿 목록·추가·공유
│  ├─ css/스타일.css
│  └─ js/
│     ├─ 암호.js          # WebCrypto 래퍼(KDF/RSA/AES) — 핵심
│     ├─ api.js           # fetch 래퍼
│     └─ 앱.js            # 화면 로직·이벤트
├─ .gitignore             # instance/, *.db, .env, __pycache__
├─ .env.example           # SECRET_KEY=changeme
├─ 📘팀비밀금고_PRD.md
└─ README.md              # 실행법 + 보안 모델 + 배운 점 + 경고
```

### 5.2 의존성 그래프 (개발 순서)
1. `backend/schema.sql`, `backend/db.py` (독립)
2. `backend/config.py` (독립)
3. `backend/routes/인증.py` → `db.py` 의존
4. `backend/routes/시크릿.py`, `공유.py` → `db.py`, 인증 세션 의존
5. `backend/app.py` → 위 전부 등록
6. `frontend/js/암호.js` (독립, WebCrypto)
7. `frontend/js/api.js` → 백엔드 API 계약 의존
8. `frontend/js/앱.js` → 암호.js + api.js 의존
9. `frontend/*.html` → js/css 연결

---

## 6. 인터페이스 계약 (변경 금지 시그니처)

### 6.1 프론트 암호 모듈 (`frontend/js/암호.js`)
```javascript
// 마스터 비번 → { authKey(base64), vaultKey(CryptoKey) }
async function deriveKeys(password, saltBytes) { ... }

// RSA 키쌍 생성 → { publicKeyB64, privateKey(CryptoKey) }
async function generateRSAKeyPair() { ... }

// vaultKey로 개인키 암호화/복호화
async function wrapPrivateKey(privateKey, vaultKey) { ... }   // → { encPrivB64, ivB64 }
async function unwrapPrivateKey(encPrivB64, ivB64, vaultKey) { ... } // → CryptoKey

// 시크릿 본문 암호화: 랜덤 K 생성 → AES-GCM → K를 공개키로 봉인
async function encryptSecret(plaintext, publicKeyB64) { ... }
// → { ciphertextB64, ivB64, wrappedKeyB64 }

// 복호화: wrappedKey를 내 개인키로 풀어 K 복원 → 본문 복호화
async function decryptSecret(ciphertextB64, ivB64, wrappedKeyB64, privateKey) { ... }
// → plaintext string

// 공유: 기존 wrappedKey(내 것)를 풀어 K 복원 → 대상 공개키로 재봉인
async function rewrapForUser(wrappedKeyB64, myPrivateKey, targetPublicKeyB64) { ... }
// → wrappedKeyB64 (대상용)
```

### 6.2 백엔드 DB 계약 (`backend/db.py`)
```python
def get_db() -> sqlite3.Connection: ...
def init_db() -> None: ...  # schema.sql 실행(없을 때만)
```

---

## 7. 프로젝트 설정 및 실행

### 7.1 requirements.txt
```
Flask
bcrypt
python-dotenv
```

### 7.2 실행 가이드 (예정)
```bash
# 1) 가상환경(venv) 생성·활성화
python -m venv .venv
source .venv/Scripts/activate      # git-bash(Windows)

# 2) 설치
pip install -r backend/requirements.txt

# 3) 실행 (프론트도 같은 서버가 서빙)
python backend/app.py              # → http://127.0.0.1:5000

# 4) 브라우저로 접속해 회원가입 2명 → 저장 → 공유 → 복호화 확인
```

### 7.3 완료(수용) 기준
- [ ] 사용자 A·B 회원가입 → 각자 로그인.
- [ ] A가 시크릿 저장 → A 금고에서 복호화되어 보임.
- [ ] A가 B에게 공유 → B가 로그인해 **자기 개인키로 복호화 성공**.
- [ ] `sqlite3 금고.db`로 직접 열어 **평문 시크릿·마스터 비번이 어디에도 없음**(암호문·해시만) 실제 확인.
- [ ] 잘못된 마스터 비번으로 로그인 실패(401).

---

## 8. 배운 점 / 주의사항 (구현하며 갱신)
- (구현 후 채움) WebCrypto의 base64 변환, IV 관리, RSA-OAEP 크기 제한 등 실전 이슈 기록.
