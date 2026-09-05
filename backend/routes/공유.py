"""공유 라우트: 사용자 공개키 조회 / 시크릿 공유.

공유는 대상의 공개키로 다시 봉인된 대칭키(wrapped_key)를 받아 shares에 추가하는 것이다.
서버는 대칭키 원본을 보지 못한다.
"""
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request, session

from db import get_db
from routes.인증 import login_required

bp = Blueprint("공유", __name__)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@bp.get("/api/users/<username>/publickey")
@login_required
def get_publickey(username):
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT username, public_key FROM users WHERE username = ?", (username.strip(),)
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        return jsonify({"error": "존재하지 않는 사용자입니다."}), 404
    return jsonify({"username": row["username"], "public_key": row["public_key"]})


@bp.post("/api/secrets/<int:secret_id>/share")
@login_required
def share_secret(secret_id):
    data = request.get_json(silent=True) or {}
    target_username = (data.get("target_username") or "").strip()
    wrapped_key = data.get("wrapped_key")
    if not target_username or not wrapped_key:
        return jsonify({"error": "target_username과 wrapped_key가 필요합니다."}), 400

    uid = session["user_id"]
    conn = get_db()
    try:
        secret = conn.execute("SELECT owner_id FROM secrets WHERE id = ?", (secret_id,)).fetchone()
        if secret is None:
            return jsonify({"error": "존재하지 않는 시크릿입니다."}), 404
        if secret["owner_id"] != uid:
            return jsonify({"error": "소유자만 공유할 수 있습니다."}), 403

        target = conn.execute(
            "SELECT id FROM users WHERE username = ?", (target_username,)
        ).fetchone()
        if target is None:
            return jsonify({"error": "공유 대상 사용자가 없습니다."}), 404

        try:
            conn.execute(
                "INSERT INTO shares (secret_id, user_id, wrapped_key, created_at) VALUES (?, ?, ?, ?)",
                (secret_id, target["id"], wrapped_key, _now()),
            )
            conn.commit()
        except Exception as e:
            if "UNIQUE" in str(e):
                return jsonify({"error": "이미 공유된 사용자입니다."}), 409
            raise
    finally:
        conn.close()

    return jsonify({"ok": True}), 201
