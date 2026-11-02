from pathlib import Path
from unittest.mock import MagicMock
import pytest

from cipherchat.realtime import admin


def test_admin_migrate(monkeypatch):
    mock_db = MagicMock()
    mock_db.verify.return_value = {"record_count": 0, "record_hash": "genesis"}
    monkeypatch.setattr(admin, "Database", lambda config: mock_db)
    monkeypatch.setenv("CIPHERCHAT_MYSQL_PASSWORD", "test")

    code = admin.main(["migrate"])
    assert code == 0
    mock_db.migrate.assert_called_once()
    mock_db.verify.assert_called_once()


def test_admin_verify(monkeypatch):
    mock_db = MagicMock()
    mock_db.verify.return_value = {"record_count": 5, "record_hash": "hash123"}
    monkeypatch.setattr(admin, "Database", lambda config: mock_db)
    monkeypatch.setenv("CIPHERCHAT_MYSQL_PASSWORD", "test")

    code = admin.main(["verify"])
    assert code == 0
    mock_db.verify.assert_called_once()


def test_admin_checkpoint(monkeypatch, tmp_path: Path):
    mock_db = MagicMock()
    out_file = tmp_path / "test_cp.json"
    mock_db.checkpoint.return_value = {"record_count": 10, "record_hash": "cphash"}
    monkeypatch.setattr(admin, "Database", lambda config: mock_db)
    monkeypatch.setenv("CIPHERCHAT_MYSQL_PASSWORD", "test")

    code = admin.main(["checkpoint", "--output", str(out_file)])
    assert code == 0
    mock_db.checkpoint.assert_called_once_with(out_file)


def test_new_run_preserves_schema_and_passes_expected_session(monkeypatch):
    db = MagicMock()
    monkeypatch.setattr(admin, "Database", lambda config: db)
    monkeypatch.setenv("CIPHERCHAT_MYSQL_PASSWORD", "test")
    assert admin.main(["new-run", "--expected-session", "alice-bob:5"]) == 0
    db.start_new_run.assert_called_once_with("alice-bob:5")
    db.migrate.assert_not_called()
