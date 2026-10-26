"""Unit tests for health.py system diagnostic monitor."""

import os
import tempfile
import pytest
from db import init_db
from health import STATUS_DEGRADED, STATUS_HEALTHY, STATUS_UNHEALTHY, check_system_health

@pytest.fixture
def test_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(db_path=path, seed=True)
    yield path
    if os.path.exists(path):
        os.remove(path)

def test_system_health_healthy_state(test_db):
    health = check_system_health(db_path=test_db)
    assert health["status"] == STATUS_HEALTHY
    assert health["subsystems"]["database"]["status"] == STATUS_HEALTHY
    assert health["subsystems"]["governor"]["status"] == STATUS_HEALTHY
    assert health["subsystems"]["executor"]["status"] == STATUS_HEALTHY
    assert health["subsystems"]["audit"]["status"] == STATUS_HEALTHY

def test_system_health_unhealthy_on_invalid_db():
    health = check_system_health(db_path="/nonexistent_dir/broken.db")
    assert health["status"] == STATUS_UNHEALTHY
    assert health["subsystems"]["database"]["status"] == STATUS_UNHEALTHY
