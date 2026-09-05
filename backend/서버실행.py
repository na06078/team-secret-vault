"""배포용 실행 스크립트 — Flask 개발 서버 대신 waitress(운영용 WSGI 서버)로 앱을 띄운다.

개발용:  python backend/app.py        (자동 새로고침, 디버그 — 나 혼자 개발할 때)
배포용:  python backend/서버실행.py    (waitress, 안정적 — 실제로 켜둘 때)

기본은 127.0.0.1:5000에만 바인딩한다. Cloudflare Tunnel이 이 주소에 붙어
바깥으로 연결하므로, 공유기 포트를 열 필요가 없다(더 안전).
"""
import os
import sys
from pathlib import Path

# backend/ 를 import 경로에 추가 (app.py와 같은 위치에서 실행되도록)
sys.path.insert(0, str(Path(__file__).resolve().parent))

from waitress import serve

import config
from app import app
from db import init_db

HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "5000"))

if __name__ == "__main__":
    init_db()
    print(f"[팀비밀금고] DB: {config.DB_PATH}")
    print(f"[팀비밀금고] waitress 배포 서버 실행: http://{HOST}:{PORT}")
    print("[팀비밀금고] 종료하려면 Ctrl+C")
    serve(app, host=HOST, port=PORT, threads=8)
