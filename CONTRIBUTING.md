# Contributing to YEMU

## Development setup

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate     Linux: source .venv/bin/activate
pip install -e ".[gui,dev]" ruff mypy
yemu doctor
```

On Linux with libvirt, create the venv with `--system-site-packages` and install `.[linux,gui,dev]`.

## Checks

Run these before opening a PR. CI runs the same checks on Ubuntu and Windows.

```bash
ruff check yemu tests
ruff format --check yemu tests
mypy
pytest -q            # GUI tests run off-screen; set QT_QPA_PLATFORM=offscreen if you have no display
```

## Guidelines

- **Keep the host safe.**
  - Treat anything that comes back from a guest as hostile.
  - `shlex.quote` every guest path.
  - Never interpolate guest-supplied strings into host commands or HTML.
  - Read [docs/threat-model.md](docs/threat-model.md) before touching the orchestrator, the backends or rule sync.
- **Cross-platform.**
  - Use `yemu.paths` for every file location. Never use relative paths or `/tmp` on the host.
  - Open text files with `encoding="utf-8"`.
  - Everything outside `yemu/gui` must import without PySide6.
- **Database changes:** append a new entry to `MIGRATIONS` in `yemu/storage/db.py`. Never edit a released migration.
- **New hypervisors:** subclass `yemu.core.vm_backend.VMBackend` and register the backend in `create_backend`. `tests/test_platform.py` checks that the interface is complete.
- **GUI progress stages:** these match orchestrator messages by prefix (`yemu/gui/pages/analyze.py`). If you change a message, update the stage list too.

## Building releases

```bash
python scripts/build.py              # wheel, sdist and a PyInstaller bundle, with smoke tests
python scripts/build.py --installer  # Windows: also the Inno Setup installer
```

Pushing a `vX.Y.Z` tag runs `.github/workflows/release.yml`, which builds on Windows and Ubuntu 22.04 and publishes a GitHub release with SHA-256 checksums.
