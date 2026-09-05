# 🔐 팀 비밀 금고 (제로지식 시크릿 볼트)

아이펠 학습 실습 — **백엔드/프론트엔드 분리 · 해시/솔트 · 공개키 · 세션키(대칭키)** 를 억지 없이 한 흐름에서 사용하는 서비스.

API 키·비밀번호 같은 민감 정보를 팀원과 공유하되, **서버 운영자조차 평문을 볼 수 없게** 만든다. 실제 Bitwarden이 쓰는 제로지식 구조의 축소판.

## 무엇이 되나
- 회원가입 / 로그인 (마스터 비번은 서버로 전송되지 않음)
- 시크릿 저장 (브라우저에서 암호화 후 전송 → 서버엔 암호문만)
- 시크릿 보기 (브라우저에서 복호화)
- 팀원에게 공유 (대상 공개키로 키 재봉인)
- 시크릿 삭제 (공유 접근도 함께 제거)

## 보안 모델 한눈에
| 배운 개념 | 하는 일 |
|---|---|
| 해시/솔트 | 서버가 로그인 증명값(authKey)을 bcrypt로 해시 저장 → DB 유출돼도 비번 복원 불가 |
| 공개키/개인키 | 대칭키를 봉인·공유. 서버는 공개키·암호문만 봄 |
| 세션키(대칭키) | AES-GCM으로 시크릿 본문을 실제 암호화 |
| 세션 토큰 | 로그인 유지(쿠키) |
| 백/프론트 분리 | 프론트=모든 암호 연산, 백=암호문·해시·세션만 |

자세한 설계는 `📘팀비밀금고_PRD.md` 참고.

## 실행 방법 (Windows / git-bash)
```bash
# 1) 가상환경 생성·활성화
python -m venv .venv
source .venv/Scripts/activate

# 2) 설치
pip install -r backend/requirements.txt

# 3) (권장) 세션키 설정 — 안 하면 실행마다 임시키(재시작 시 로그인 풀림)
cp .env.example .env
python -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))" > .env

# 4) 실행
cd backend && python app.py
#   → http://127.0.0.1:5000
```

## ⚠️ 주의
- **마스터 비번을 잊으면 복구 불가** — 제로지식의 본질적 결과.
- **로컬 실습 전용**: `127.0.0.1`에서만. 실제 배포하려면 HTTPS 필수(WebCrypto가 secure context를 요구).
- `salt` 조회 API로 사용자명 존재 여부가 노출됨(실습 단순화, 감수).
- 제목(title)은 평문 저장 — 민감정보를 제목에 넣지 말 것.

## 폴더 구조
```
팀비밀금고/
├─ backend/          # Flask JSON API (평문을 절대 다루지 않음)
│  ├─ app.py  config.py  db.py  schema.sql
│  └─ routes/ 인증.py  시크릿.py  공유.py
├─ frontend/         # 화면 + 모든 암호 연산
│  ├─ index.html
│  ├─ css/스타일.css
│  └─ js/ 암호.js(핵심)  api.js  앱.js
├─ 📘팀비밀금고_PRD.md
└─ README.md
```
