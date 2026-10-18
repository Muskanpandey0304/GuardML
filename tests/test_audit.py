from __future__ import annotations
import os
import sqlite3
import tempfile
import pytest


@pytest.fixture
def temp_db(monkeypatch, tmp_path):
    db = tmp_path / 'test_guardml.db'
    monkeypatch.setenv('GUARDML_DB', str(db))
    import importlib
    import guardml.audit.log as log_module
    importlib.reload(log_module)
    log_module.ensure_tables()
    return log_module.AuditLog()


class TestAuditLog:
    def test_log_and_retrieve(self, temp_db):
        log = temp_db
        eid = log.log_event(
            session_id='sess1',
            tool='mlflow_list_runs',
            args={'experiment_name': 'fraud_detection'},
            verdict='ALLOW',
            risk_score=10,
            risk_label='low',
            result_summary='3 runs returned',
        )
        assert eid is not None
        entries = log.get_session('sess1')
        assert len(entries) == 1
        assert entries[0]['tool'] == 'mlflow_list_runs'

    def test_chain_integrity_passes(self, temp_db):
        log = temp_db
        for i in range(5):
            log.log_event(session_id='sess2', tool=f'tool_{i}', args={}, verdict='ALLOW', risk_score=10, risk_label='low')
        result = log.verify_chain()
        assert result['ok'] is True
        assert result['checked'] == 5

    def test_tamper_detection(self, temp_db, monkeypatch, tmp_path):
        log = temp_db
        import guardml.audit.log as log_module
        db_path = log_module.DB_PATH
        for i in range(3):
            log.log_event(session_id='sess3', tool=f'tool_{i}', args={}, verdict='ALLOW', risk_score=10, risk_label='low')
        conn = sqlite3.connect(str(db_path))
        conn.execute("UPDATE audit_log SET result_summary='TAMPERED' WHERE seq=1")
        conn.commit()
        conn.close()
        result = log.verify_chain()
        assert result['ok'] is False
        assert result['first_tampered_seq'] == 1

    def test_concurrent_appends_keep_chain_valid(self, temp_db):
        """Parallel sessions must not read the same chain tail and fork the chain."""
        from concurrent.futures import ThreadPoolExecutor
        log = temp_db

        def write(i):
            log.log_event(session_id=f's{i % 4}', tool=f't{i}', args={}, verdict='ALLOW')

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(write, range(40)))

        result = log.verify_chain()
        assert result['ok'] is True
        assert result['checked'] == 40

    def test_empty_chain_ok(self, temp_db):
        log = temp_db
        result = log.verify_chain()
        assert result['ok'] is True
        assert result['checked'] == 0
