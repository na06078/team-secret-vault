"""SQLite 연결/초기화. 요청마다 연결을 열고 닫는 단순 구조(실습용)."""
import sqlite3
from pathlib import Path

import config


def get_db() -> sqlite3.Connection:
    """새 SQLite 연결을 반환한다. row를 dict처럼 다루도록 row_factory 설정."""
    config.INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    """schema.sql을 실행해 테이블을 만든다(없을 때만)."""
    schema_path = Path(__file__).resolve().parent / "schema.sql"
    sql = schema_path.read_text(encoding="utf-8")
    conn = get_db()
    try:
        conn.executescript(sql)
        conn.commit()
        _migrate(conn)
    finally:
        conn.close()


def _migrate(conn: sqlite3.Connection) -> None:
    """기존 DB에 복구 키 컬럼이 없으면 추가한다(무손실 마이그레이션)."""
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(users)")}
    add = {
        "recovery_salt": "TEXT",
        "recovery_hash": "TEXT",
        "enc_priv_recovery": "TEXT",
        "enc_priv_recovery_iv": "TEXT",
    }
    for name, typ in add.items():
        if name not in cols:
            conn.execute(f"ALTER TABLE users ADD COLUMN {name} {typ}")
    conn.commit()
