import runpy

import pytest


def test_run_ingestion_requires_input_file(monkeypatch):
    monkeypatch.setenv("VPAP_AUDIT_API_URL", "https://example.com")
    monkeypatch.delenv("VPAP_INPUT_FILE", raising=False)

    with pytest.raises(RuntimeError, match="VPAP_INPUT_FILE must be configured"):
        runpy.run_path("scripts/run_ingestion.py", run_name="__main__")


def test_run_ingestion_requires_tenant_id(monkeypatch, tmp_path):
    input_file = tmp_path / "input.xlsx"
    input_file.touch()

    monkeypatch.setenv("VPAP_INPUT_FILE", str(input_file))
    monkeypatch.setenv("VPAP_AUDIT_API_URL", "https://example.com")
    monkeypatch.setenv("VPAP_AUDIT_API_TOKEN", "test-token")
    monkeypatch.delenv("VPAP_TENANT_ID", raising=False)

    with pytest.raises(RuntimeError, match="VPAP_TENANT_ID must be configured"):
        runpy.run_path("scripts/run_ingestion.py", run_name="__main__")

def test_run_ingestion_rejects_missing_input_file(monkeypatch, tmp_path):
    missing_file = tmp_path / "missing.xlsx"

    monkeypatch.setenv("VPAP_AUDIT_API_URL", "https://example.com")
    monkeypatch.setenv("VPAP_INPUT_FILE", str(missing_file))
    monkeypatch.setenv("VPAP_TENANT_ID", "tenant-001")

    with pytest.raises(FileNotFoundError, match="Input file does not exist"):
        runpy.run_path("scripts/run_ingestion.py", run_name="__main__")


def test_run_ingestion_rejects_non_xlsx_input(monkeypatch, tmp_path):
    input_file = tmp_path / "input.csv"
    input_file.touch()

    monkeypatch.setenv("VPAP_AUDIT_API_URL", "https://example.com")
    monkeypatch.setenv("VPAP_INPUT_FILE", str(input_file))
    monkeypatch.setenv("VPAP_TENANT_ID", "tenant-001")

    with pytest.raises(ValueError, match="Only .xlsx input files are supported"):
        runpy.run_path("scripts/run_ingestion.py", run_name="__main__")