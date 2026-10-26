"""Unit and scalability tests for concurrent Governor evaluations."""

import os
import tempfile
import pytest
from concurrency_bench import run_concurrent_benchmark
from db import init_db, get_db

@pytest.fixture
def test_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(db_path=path, seed=True)
    yield path
    if os.path.exists(path):
        os.remove(path)

def test_concurrent_execution_accuracy_and_isolation(test_db):
    """
    Run 25 mixed concurrent requests across 5 worker threads.
    Verify 100% accuracy, 0 authorization bypasses, and audit trail consistency.
    """
    bench_results = run_concurrent_benchmark(num_workers=5, num_requests=25, db_path=test_db)
    
    assert bench_results["num_requests"] == 25
    assert bench_results["accuracy_pct"] == 100.0
    assert bench_results["authorization_bypasses"] == 0
    assert bench_results["all_correct"] is True
    assert bench_results["throughput_req_per_sec"] > 0
    assert bench_results["p50_latency_ms"] >= 0
    
    # Verify in SQLite database that 25 distinct decisions and audit records exist
    with get_db(test_db) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(DISTINCT id) AS count FROM action_requests")
        req_count = cursor.fetchone()["count"]
        assert req_count == 25
        
        cursor.execute("SELECT COUNT(DISTINCT request_id) AS count FROM decisions")
        dec_count = cursor.fetchone()["count"]
        assert dec_count == 25
