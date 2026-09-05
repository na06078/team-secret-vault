"""인증 라우트: 회원가입 / 솔트조회 / 로그인 / 로그아웃.

보안 핵심: 서버는 마스터 비번을 절대 받지 않는다.
클라이언트가 PBKDF2로 유도한 authKey만 받아, 그걸 다시 bcrypt로 해시해 저장한다.
"""
from datetime import datetime, timezone
from functools import wraps

import bcrypt
from flask import Blueprint, jsonify, request, session

from db import get_db

bp = Blueprint("인증", __name__)


def login_required(view):
    """세션에 user_id가 없으면 401을 반환하는 데코레이터."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "로그인이 필요합니다."}), 401
        return view(*args, **kwargs)

    return wrapped


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@bp.post("/api/register")
def register():
    data = request.get_json(silent=True) or {}
    required = ["username", "salt", "authKey", "public_key", "enc_priv", "enc_priv_iv"]
    missing = [k for k in required if not data.get(k)]
    if missing:
        return jsonify({"error": f"필드 누락: {', '.join(missing)}"}), 400

    username = data["username"].strip()
    if not username:
        return jsonify({"error": "사용자명이 비어 있습니다."}), 400

    # authKey를 bcrypt로 해시(솔트 자동 포함). authKey는 base64 문자열.
    auth_hash = bcrypt.hashpw(data["authKey"].encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    conn = get_db()
    try:
        conn.execute(
            """INSERT INTO users
               (username, salt, auth_hash, public_key, enc_priv, enc_priv_iv, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (username, data["salt"], auth_hash, data["public_key"],
             data["enc_priv"], data["enc_priv_iv"], _now()),
        )
        conn.commit()
    except Exception as e:  # UNIQUE 위반 등
        if "UNIQUE" in str(e):
            return jsonify({"error": "이미 존재하는 사용자명입니다."}), 409
        raise
    finally:
        conn.close()

    return jsonify({"ok": True}), 201


@bp.get("/api/salt")
def get_salt():
    # ⚠️ 실습 단순화: 없는 사용자는 404 → 사용자 존재 여부가 노출됨(감수).
    username = (request.args.get("username") or "").strip()
    if not username:
        return jsonify({"error": "username이 필요합니다."}), 400

    conn = get_db()
    try:
        row = conn.execute("SELECT salt FROM users WHERE username = ?", (username,)).fetchone()
    finally:
        conn.close()

    if row is None:
        return jsonify({"error": "존재하지 않는 사용자입니다."}), 404
    return jsonify({"salt": row["salt"]})


@bp.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    auth_key = data.get("authKey")
    if not username or not auth_key:
        return jsonify({"error": "username과 authKey가 필요합니다."}), 400

    conn = get_db()
    try:
        row = conn.execute(
            "SELECT id, auth_hash, enc_priv, enc_priv_iv FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    finally:
        conn.close()

    if row is None or not bcrypt.checkpw(auth_key.encode("utf-8"), row["auth_hash"].encode("utf-8")):
        return jsonify({"error": "사용자명 또는 비밀번호가 올바르지 않습니다."}), 401

    session.clear()
    session["user_id"] = row["id"]
    session["username"] = username
    return jsonify({
        "ok": True,
        "username": username,
        "enc_priv": row["enc_priv"],
        "enc_priv_iv": row["enc_priv_iv"],
    })


@bp.post("/api/logout")
def logout():
    session.clear()
    return jsonify({"ok": True})


@bp.get("/api/me")
def me():
    if "user_id" not in session:
        return jsonify({"logged_in": False})
    return jsonify({"logged_in": True, "username": session.get("username")})
