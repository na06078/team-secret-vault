"""설정 로드. .env가 있으면 읽고, 없으면 개발용 기본값을 쓴다."""
import os
import secrets
from pathlib import Path

from dotenv import load_dotenv

# 프로젝트 루트(.env는 backend/ 상위, 즉 팀비밀금고/ 에 둔다)
BASE_DIR = Path(__file__).resolve().parent          # backend/
PROJECT_ROOT = BASE_DIR.parent                       # 팀비밀금고/

load_dotenv(PROJECT_ROOT / ".env")

# 세션 쿠키 서명용 키. .env에 없으면 실행마다 임시 키 생성(재시작 시 로그인 풀림).
SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# SQLite 파일 위치
INSTANCE_DIR = BASE_DIR / "instance"
DB_PATH = INSTANCE_DIR / "금고.db"
