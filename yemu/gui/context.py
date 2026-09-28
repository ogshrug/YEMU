"""
Shared state for the Qt app, and the bridge between Qt's main thread and the
single asyncio loop (AsyncRunner) where the DB, backends and orchestrator live.
"""

import asyncio
import logging

from PySide6.QtCore import QObject, Signal

from yemu import config as yemu_config
from yemu.core.async_runner import AsyncRunner
from yemu.core.vm_backend import create_backend
from yemu.storage.db import Database

logger = logging.getLogger(__name__)


class Bridge(QObject):
    """Runs coroutines on the AsyncRunner loop and delivers results on the Qt main thread."""

    _done = Signal(object, object, object, object)  # on_result, on_error, result, error

    def __init__(self, runner):
        super().__init__()
        self.runner = runner
        self._done.connect(self._dispatch)

    def call(self, coro, on_result=None, on_error=None):
        def finished(result, error):
            self._done.emit(on_result, on_error, result, error)

        return self.runner.submit(coro, on_done=finished)

    def call_sync(self, fn, *args, on_result=None, on_error=None):
        """Run a blocking function in a worker thread (via the runner loop)."""
        return self.call(asyncio.to_thread(fn, *args), on_result, on_error)

    def post(self, fn):
        """Run fn() on the Qt main thread; safe to call from any thread."""
        self._done.emit(lambda _: fn(), None, None, None)

    def _dispatch(self, on_result, on_error, result, error):
        if error is not None:
            if on_error:
                on_error(error)
            else:
                logger.error(f"Background task failed: {error}")
        elif on_result:
            on_result(result)


class LogBus(QObject):
    """Thread-safe sink for orchestrator/backend messages (their ui_callback)."""

    message = Signal(str, str)

    def __call__(self, msg, severity="INFO"):
        self.message.emit(str(msg), severity)


class AppContext(QObject):
    backend_changed = Signal()
    analyses_changed = Signal()
    config_changed = Signal()
    update_available = Signal(object)  # release dict from core.updates
    rules_updated = Signal(object)  # sync manifest

    def __init__(self, db_path=None):
        super().__init__()
        self.config = yemu_config.load()
        self.runner = AsyncRunner(name="yemu-gui")
        self.bridge = Bridge(self.runner)
        self.log = LogBus()
        self.db = Database(db_path)
        self.db_ready = False
        self.backend = create_backend(self.config["vm"]["backend"], ui_callback=self.log, config=self.config)
        self.analysis_running = False
        self.rules_syncing = False

    def connect_db(self, on_ready=None):
        def ready(_):
            self.db_ready = True
            if on_ready:
                on_ready()

        self.bridge.call(self.db.connect(), ready, lambda e: self.log(f"Database connection failed: {e}", "CRITICAL"))

    def reload_config(self):
        self.config = yemu_config.load()
        self.backend = create_backend(self.config["vm"]["backend"], ui_callback=self.log, config=self.config)
        self.config_changed.emit()
        self.backend_changed.emit()

    def run_background_updates(self):
        """Startup: re-sync YARA rules if due and look for a newer YEMU, both off the UI thread."""
        from yemu.core import updates

        if updates.rules_update_due(self.config):
            self.sync_rules(automatic=True)
        if updates.app_check_due(self.config):
            self.check_app_update(silent=True)

    def sync_rules(self, automatic=False, progress=None, on_done=None, on_error=None):
        from yemu.core import updates

        if self.rules_syncing:
            return
        self.rules_syncing = True

        def done(manifest):
            self.rules_syncing = False
            self.rules_updated.emit(manifest)
            if on_done:
                on_done(manifest)

        def failed(error):
            self.rules_syncing = False
            if automatic:
                self.log(f"Automatic YARA rule update failed: {error}", "WARN")
            if on_error:
                on_error(error)

        self.bridge.call_sync(updates.update_rules, self.config, progress, on_result=done, on_error=failed)

    def check_app_update(self, silent=True, on_done=None):
        """Emits update_available for a newer release (unless the user skipped that version)."""
        from yemu.core import updates

        def done(release):
            skipped = updates.load_state().get("skipped_version")
            if release and not (silent and release["version"] == skipped):
                self.update_available.emit(release)
            if on_done:
                on_done(release, None)

        def failed(error):
            if on_done:
                on_done(None, error)

        self.bridge.call_sync(
            updates.check_for_app_update, self.config["updates"]["include_prereleases"], on_result=done, on_error=failed
        )

    def backend_label(self):
        name = self.backend.name
        if name == "qemu":
            return f"qemu ({self.backend.accel})"
        if name == "mock":
            return "mock (no hypervisor)"
        return name

    def shutdown(self):
        try:
            self.runner.run(self.db.close(), timeout=5)
        except Exception:
            pass
        self.runner.stop()
