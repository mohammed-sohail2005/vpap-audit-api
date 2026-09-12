"""
tests/test_batch_relationship.py
-----------------------------------
Proves the finding_instance.batch_id migration actually works,
against a FRESH database (not the manually-edited production one).

This is the specific evidence Hidayat asked for: not just "the
column exists," but "the foreign key is genuinely enforced."

Run standalone with:
    pytest tests/test_batch_relationship.py -v

Requires VPAP_AUDIT_DSN pointing at a database that has already
had migrations/ applied (see run_migrations.py) - CI does this
automatically before calling pytest.
"""

import os
import uuid
import psycopg
import pytest


@pytest.fixture
def conn():
    dsn = os.environ["VPAP_AUDIT_DSN"]
    connection = psycopg.connect(dsn, prepare_threshold=None)
    yield connection
    connection.close()


def test_batch_id_column_exists(conn):
    """Confirms the migration actually added the column."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT column_name, data_type FROM information_schema.columns
            WHERE table_name = 'finding_instance' AND column_name = 'batch_id'
            """
        )
        row = cur.fetchone()
    assert row is not None, "batch_id column was not created by the migration"
    assert row[1] == "uuid", f"Expected batch_id to be uuid, got {row[1]}"


def test_batch_id_foreign_key_exists(conn):
    """Confirms the FK constraint itself exists (not just documented in a comment)."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT constraint_name FROM information_schema.table_constraints
            WHERE table_name = 'finding_instance'
            AND constraint_type = 'FOREIGN KEY'
            AND constraint_name = 'fk_finding_instance_batch'
            """
        )
        row = cur.fetchone()
    assert row is not None, "fk_finding_instance_batch constraint was not created"


def test_batch_id_index_exists(conn):
    """Confirms the index exists, for query performance on batch lookups."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT indexname FROM pg_indexes
            WHERE tablename = 'finding_instance' AND indexname = 'idx_finding_instance_batch'
            """
        )
        row = cur.fetchone()
    assert row is not None, "idx_finding_instance_batch index was not created"


def test_valid_batch_id_is_accepted(conn):
    """A finding pointing at a REAL ingestion_batch should insert successfully."""
    batch_id = str(uuid.uuid4())
    finding_id = str(uuid.uuid4())

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO ingestion_batch (id, tenant_id, source_system, source_type, status)
            VALUES (%s, 'ci-test-tenant', 'WIZ', 'API', 'COMPLETED')
            """,
            (batch_id,),
        )
        cur.execute(
            """
            INSERT INTO finding_instance
                (id, tenant_id, idempotency_key, source_system, source_finding_id,
                 cve_id, asset_id, batch_id)
            VALUES (%s, 'ci-test-tenant', %s, 'WIZ', 'ci-test-finding',
                    'CVE-2026-00000', 'ci-test-asset', %s)
            """,
            (finding_id, str(uuid.uuid4()), batch_id),
        )
    conn.commit()

    with conn.cursor() as cur:
        cur.execute("SELECT batch_id FROM finding_instance WHERE id = %s", (finding_id,))
        row = cur.fetchone()
    assert row is not None
    assert str(row[0]) == batch_id


def test_invalid_batch_id_is_rejected(conn):
    """A finding pointing at a NONEXISTENT ingestion_batch must be rejected by the FK."""
    fake_batch_id = str(uuid.uuid4())  # deliberately never inserted into ingestion_batch
    finding_id = str(uuid.uuid4())

    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO finding_instance
                    (id, tenant_id, idempotency_key, source_system, source_finding_id,
                     cve_id, asset_id, batch_id)
                VALUES (%s, 'ci-test-tenant', %s, 'WIZ', 'ci-test-finding-invalid',
                        'CVE-2026-00001', 'ci-test-asset', %s)
                """,
                (finding_id, str(uuid.uuid4()), fake_batch_id),
            )
    conn.rollback()  # required after a failed statement, before the next test can use conn


def test_query_findings_by_batch(conn):
    """Confirms the whole point of batch_id: retrieving all findings from one batch."""
    batch_id = str(uuid.uuid4())

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO ingestion_batch (id, tenant_id, source_system, source_type, status)
            VALUES (%s, 'ci-test-tenant', 'WIZ', 'API', 'COMPLETED')
            """,
            (batch_id,),
        )
        for i in range(3):
            cur.execute(
                """
                INSERT INTO finding_instance
                    (id, tenant_id, idempotency_key, source_system, source_finding_id,
                     cve_id, asset_id, batch_id)
                VALUES (%s, 'ci-test-tenant', %s, 'WIZ', %s, %s, 'ci-test-asset', %s)
                """,
                (str(uuid.uuid4()), str(uuid.uuid4()), f"finding-{i}", f"CVE-2026-{i:05d}", batch_id),
            )
    conn.commit()

    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM finding_instance WHERE batch_id = %s", (batch_id,))
        count = cur.fetchone()[0]
    assert count == 3, f"Expected 3 findings linked to the batch, found {count}"