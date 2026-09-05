"""시크릿 라우트: 목록 / 생성 / 삭제.

서버는 암호문(ciphertext), IV, 봉인된 대칭키(wrapped_key)만 다룬다.
평문 시크릿과 대칭키 원본은 서버에 절대 오지 않는다.
"""
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request, session

from db import get_db
from routes.인증 import login_required

bp = Blueprint("시크릿", __name__)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@bp.get("/api/secrets")
@login_required
def list_secrets():
    """내가 접근 가능한(shares에 내 레코드가 있는) 시크릿을 반환."""
    uid = session["user_id"]
    conn = get_db()
    try:
        rows = conn.execute(
            """SELECT s.id, s.title, s.ciphertext, s.iv, s.owner_id,
                      sh.wrapped_key, u.username AS owner_username
               FROM shares sh
               JOIN secrets s ON s.id = sh.secret_id
               JOIN users u   ON u.id = s.owner_id
               WHERE sh.user_id = ?
               ORDER BY s.created_at DESC""",
            (uid,),
        ).fetchall()
    finally:
        conn.close()

    result = [{
        "id": r["id"],
        "title": r["title"],
        "ciphertext": r["ciphertext"],
        "iv": r["iv"],
        "wrapped_key": r["wrapped_key"],
        "owner_username": r["owner_username"],
        "is_owner": r["owner_id"] == uid,
    } for r in rows]
    return jsonify(result)


@bp.post("/api/secrets")
@login_required
def create_secret():
    data = request.get_json(silent=True) or {}
    required = ["title", "ciphertext", "iv", "wrapped_key"]
    missing = [k for k in required if not data.get(k)]
    if missing:
        return jsonify({"error": f"필드 누락: {', '.join(missing)}"}), 400

    title = data["title"].strip()
    if not title:
        return jsonify({"error": "제목이 비어 있습니다."}), 400

    uid = session["user_id"]
    conn = get_db()
    try:
        cur = conn.execute(
            "INSERT INTO secrets (owner_id, title, ciphertext, iv, created_at) VALUES (?, ?, ?, ?, ?)",
            (uid, title, data["ciphertext"], data["iv"], _now()),
        )
        secret_id = cur.lastrowid
        # 소유자 본인도 shares에 자기 wrapped_key 레코드를 가진다.
        conn.execute(
            "INSERT INTO shares (secret_id, user_id, wrapped_key, created_at) VALUES (?, ?, ?, ?)",
            (secret_id, uid, data["wrapped_key"], _now()),
        )
        conn.commit()
    finally:
        conn.close()

    return jsonify({"id": secret_id}), 201


@bp.delete("/api/secrets/<int:secret_id>")
@login_required
def delete_secret(secret_id):
    uid = session["user_id"]
    conn = get_db()
    try:
        row = conn.execute("SELECT owner_id FROM secrets WHERE id = ?", (secret_id,)).fetchone()
        if row is None:
            return jsonify({"error": "존재하지 않는 시크릿입니다."}), 404
        if row["owner_id"] != uid:
            return jsonify({"error": "소유자만 삭제할 수 있습니다."}), 403
        # 관련 shares 전부 삭제 → 공유받은 팀원 접근도 함께 사라짐(실습 단순화 결정).
        conn.execute("DELETE FROM shares WHERE secret_id = ?", (secret_id,))
        conn.execute("DELETE FROM secrets WHERE id = ?", (secret_id,))
        conn.commit()
    finally:
        conn.close()

    return jsonify({"ok": True})
