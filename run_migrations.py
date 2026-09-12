"""
run_migrations.py
-------------------
Applies every .sql file in migrations/, in filename order (0001,
0002, ...), against whatever database VPAP_AUDIT_DSN points to.

Tracks which migrations have already run in a migration_history
table, so re-running this script is always safe - already-applied
migrations are skipped automatically.

Usage:
    py run_migrations.py

Used by:
  - You, manually, when adding a new migration locally
  - CI (.github/workflows/ci.yml), against a fresh throwaway
    Postgres database, to prove the migrations actually work
    from an empty database - not just "it works because Sohail
    already fixed the live database by hand."
"""

import os
import sys
from pathlib import Path
import psycopg
from dotenv import load_dotenv

load_dotenv()

MIGRATIONS_DIR = Path(__file__).parent / "migrations"


def get_dsn() -> str:
    dsn = os.environ.get("VPAP_AUDIT_DSN")
    if not dsn:
        print("ERROR: VPAP_AUDIT_DSN is not set.")
        sys.exit(1)
    return dsn


def ensure_history_table(conn):
    """Tracks which migration files have already been applied."""
    with conn.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS migration_history (
                filename    text PRIMARY KEY,
                applied_at  timestamptz NOT NULL DEFAULT now()
            )
            """
        )
    conn.commit()


def already_applied(conn, filename: str) -> bool:
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM migration_history WHERE filename = %s", (filename,))
        return cur.fetchone() is not None


def mark_applied(conn, filename: str):
    with conn.cursor() as cur:
        cur.execute("INSERT INTO migration_history (filename) VALUES (%s)", (filename,))
    conn.commit()


def run_migrations():
    dsn = get_dsn()
    migration_files = sorted(MIGRATIONS_DIR.glob("*.sql"))

    if not migration_files:
        print("No migration files found in migrations/.")
        return

    with psycopg.connect(dsn, prepare_threshold=None) as conn:
        ensure_history_table(conn)

        for path in migration_files:
            filename = path.name

            if already_applied(conn, filename):
                print(f"  SKIP  {filename} (already applied)")
                continue

            sql = path.read_text()
            print(f"  APPLY {filename} ...", end=" ")
            try:
                with conn.cursor() as cur:
                    cur.execute(sql)
                conn.commit()
                mark_applied(conn, filename)
                print("OK")
            except Exception as e:
                conn.rollback()
                print(f"FAILED\n{e}")
                sys.exit(1)

    print("\nAll migrations applied successfully.")


if __name__ == "__main__":
    run_migrations()