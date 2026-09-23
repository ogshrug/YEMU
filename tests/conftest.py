import pytest


@pytest.fixture(autouse=True)
def isolated_yemu_home(tmp_path, monkeypatch):
    """Keep every test's DB, reports, rules and config out of the real user profile."""
    home = tmp_path / "yemu-home"
    monkeypatch.setenv("YEMU_HOME", str(home))
    monkeypatch.delenv("YEMU_VM_DIR", raising=False)
    return home
