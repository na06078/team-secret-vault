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

    # 복구 키 필드(선택). v2 프론트는 항상 보내지만, 없으면 복구 미설정으로 가입 허용.
    recovery_salt = data.get("recovery_salt")
    recovery_auth_key = data.get("recovery_auth_key")
    enc_priv_recovery = data.get("enc_priv_recovery")
    enc_priv_recovery_iv = data.get("enc_priv_recovery_iv")
    recovery_hash = None
    if recovery_auth_key:
        recovery_hash = bcrypt.hashpw(recovery_auth_key.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    conn = get_db()
    try:
        conn.execute(
            """INSERT INTO users
               (username, salt, auth_hash, public_key, enc_priv, enc_priv_iv,
                recovery_salt, recovery_hash, enc_priv_recovery, enc_priv_recovery_iv, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (username, data["salt"], auth_hash, data["public_key"],
             data["enc_priv"], data["enc_priv_iv"],
             recovery_salt, recovery_hash, enc_priv_recovery, enc_priv_recovery_iv, _now()),
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


# ==================== 복구 키(Recovery Key) ====================

@bp.get("/api/recovery-salt")
def recovery_salt():
    """복구 화면용: username의 recovery_salt 반환. 미설정이면 404."""
    username = (request.args.get("username") or "").strip()
    if not username:
        return jsonify({"error": "username이 필요합니다."}), 400
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT recovery_salt FROM users WHERE username = ?", (username,)
        ).fetchone()
    finally:
        conn.close()
    if row is None or not row["recovery_salt"]:
        return jsonify({"error": "복구 키가 설정되지 않은 계정입니다."}), 404
    return jsonify({"recovery_salt": row["recovery_salt"]})


@bp.post("/api/recovery-priv")
def recovery_priv():
    """복구 키 검증 통과 시에만 개인키 복구 사본(암호문)을 내려준다."""
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    recovery_auth_key = data.get("recovery_auth_key")
    if not username or not recovery_auth_key:
        return jsonify({"error": "username과 recovery_auth_key가 필요합니다."}), 400
    conn = get_db()
    try:
        row = conn.execute(
            """SELECT recovery_hash, enc_priv_recovery, enc_priv_recovery_iv
               FROM users WHERE username = ?""",
            (username,),
        ).fetchone()
    finally:
        conn.close()
    if (row is None or not row["recovery_hash"]
            or not bcrypt.checkpw(recovery_auth_key.encode("utf-8"), row["recovery_hash"].encode("utf-8"))):
        return jsonify({"error": "복구 키가 올바르지 않습니다."}), 401
    return jsonify({
        "enc_priv_recovery": row["enc_priv_recovery"],
        "enc_priv_recovery_iv": row["enc_priv_recovery_iv"],
    })


@bp.post("/api/recover")
def recover():
    """복구 키로 인가된 사용자의 마스터 비번 재설정(새 salt/authKey/enc_priv 갱신)."""
    data = request.get_json(silent=True) or {}
    required = ["username", "recovery_auth_key", "new_salt", "new_auth_key",
                "new_enc_priv", "new_enc_priv_iv"]
    missing = [k for k in required if not data.get(k)]
    if missing:
        return jsonify({"error": f"필드 누락: {', '.join(missing)}"}), 400
    username = data["username"].strip()

    conn = get_db()
    try:
        row = conn.execute("SELECT recovery_hash FROM users WHERE username = ?", (username,)).fetchone()
        if (row is None or not row["recovery_hash"]
                or not bcrypt.checkpw(data["recovery_auth_key"].encode("utf-8"), row["recovery_hash"].encode("utf-8"))):
            return jsonify({"error": "복구 키가 올바르지 않습니다."}), 401
        new_auth_hash = bcrypt.hashpw(data["new_auth_key"].encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        conn.execute(
            """UPDATE users
               SET salt = ?, auth_hash = ?, enc_priv = ?, enc_priv_iv = ?
               WHERE username = ?""",
            (data["new_salt"], new_auth_hash, data["new_enc_priv"], data["new_enc_priv_iv"], username),
        )
        conn.commit()
    finally:
        conn.close()
    return jsonify({"ok": True})


@bp.post("/api/recovery-key/reset")
@login_required
def recovery_key_reset():
    """로그인 상태에서 복구 키를 새로 발급(복구 관련 컬럼 4개 덮어쓰기)."""
    data = request.get_json(silent=True) or {}
    required = ["recovery_salt", "recovery_auth_key", "enc_priv_recovery", "enc_priv_recovery_iv"]
    missing = [k for k in required if not data.get(k)]
    if missing:
        return jsonify({"error": f"필드 누락: {', '.join(missing)}"}), 400
    recovery_hash = bcrypt.hashpw(data["recovery_auth_key"].encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    conn = get_db()
    try:
        conn.execute(
            """UPDATE users
               SET recovery_salt = ?, recovery_hash = ?, enc_priv_recovery = ?, enc_priv_recovery_iv = ?
               WHERE id = ?""",
            (data["recovery_salt"], recovery_hash, data["enc_priv_recovery"],
             data["enc_priv_recovery_iv"], session["user_id"]),
        )
        conn.commit()
    finally:
        conn.close()
    return jsonify({"ok": True})
