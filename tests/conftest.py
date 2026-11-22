"""Shared pytest fixtures."""
import pytest


@pytest.fixture(autouse=True)
def _reset_troubleshoot_store():
    """Every test starts with an empty in-memory troubleshooting store."""
    from app.troubleshoot import store

    store.reset()
    yield
    store.reset()
