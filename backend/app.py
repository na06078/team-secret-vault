"""팀 비밀 금고 — Flask 진입점.

- /api/* : JSON API (인증/시크릿/공유)
- 그 외   : frontend/ 정적 파일 서빙 (같은 오리진 → CORS 불필요)
실행: python app.py  → http://127.0.0.1:5000
"""
from pathlib import Path

from flask import Flask, send_from_directory

import config
from db import init_db
from routes.인증 import bp as auth_bp
from routes.시크릿 import bp as secrets_bp
from routes.공유 import bp as share_bp

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

app = Flask(__name__, static_folder=None)
app.config["SECRET_KEY"] = config.SECRET_KEY
# 로컬 http 실습이므로 Secure 쿠키는 끄고, JS가 세션 쿠키를 읽을 필요는 없다.
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_HTTPONLY"] = True

app.register_blueprint(auth_bp)
app.register_blueprint(secrets_bp)
app.register_blueprint(share_bp)


@app.get("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.get("/<path:filename>")
def frontend_files(filename):
    """frontend/ 안의 정적 파일(html/css/js)을 서빙."""
    return send_from_directory(FRONTEND_DIR, filename)


if __name__ == "__main__":
    init_db()
    print(f"[팀비밀금고] DB: {config.DB_PATH}")
    print("[팀비밀금고] http://127.0.0.1:5000 에서 실행 중")
    app.run(host="127.0.0.1", port=5000, debug=True)
