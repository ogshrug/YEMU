import re
from pathlib import Path

from PySide6.QtCore import QObject, QRegularExpression, Qt, Signal
from PySide6.QtGui import QColor, QFont, QSyntaxHighlighter, QTextCharFormat
from PySide6.QtWidgets import (QHBoxLayout, QInputDialog, QLineEdit, QMessageBox, QPlainTextEdit, QProgressBar,
                               QSplitter, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)

from yemu import paths
from yemu.gui import theme
from yemu.gui.widgets import button, card, label, page_header

try:
    import yara
except ImportError:
    yara = None

KEYWORDS = ("rule private global import include meta strings condition and or not all any of them for in at "
            "filesize entrypoint true false nocase wide ascii fullword xor base64 base64wide matches contains "
            "startswith endswith icontains iequals none defined").split()


class YaraHighlighter(QSyntaxHighlighter):
    def __init__(self, document, dark):
        super().__init__(document)

        def fmt(color, bold=False, italic=False):
            f = QTextCharFormat()
            f.setForeground(QColor(color))
            if bold:
                f.setFontWeight(QFont.Bold)
            f.setFontItalic(italic)
            return f

        palette = ({"kw": "#c792ea", "str": "#c3e88d", "var": "#82aaff", "num": "#f78c6c", "cmt": "#6b7280", "hex": "#ffcb6b"}
                   if dark else
                   {"kw": "#7c3aed", "str": "#15803d", "var": "#1d4ed8", "num": "#c2410c", "cmt": "#6b7280", "hex": "#a16207"})
        self.rules = [
            (QRegularExpression(r"\b(" + "|".join(KEYWORDS) + r")\b"), fmt(palette["kw"], bold=True)),
            (QRegularExpression(r"[$#@!][A-Za-z0-9_*]*"), fmt(palette["var"])),
            (QRegularExpression(r"\b(0x[0-9a-fA-F]+|\d+(KB|MB)?)\b"), fmt(palette["num"])),
            (QRegularExpression(r"\{[0-9a-fA-F?\s\[\]\-|()~]+\}"), fmt(palette["hex"])),
            (QRegularExpression(r'"(\\.|[^"\\])*"'), fmt(palette["str"])),
            (QRegularExpression(r"/(\\.|[^/\\\n])+/[isx]*"), fmt(palette["str"])),
            (QRegularExpression(r"//[^\n]*"), fmt(palette["cmt"], italic=True)),
        ]
        self.comment = fmt(palette["cmt"], italic=True)

    def highlightBlock(self, text):
        for rx, f in self.rules:
            it = rx.globalMatch(text)
            while it.hasNext():
                m = it.next()
                self.setFormat(m.capturedStart(), m.capturedLength(), f)
        # /* block comments */
        self.setCurrentBlockState(0)
        start = 0 if self.previousBlockState() == 1 else text.find("/*")
        while start >= 0:
            end = text.find("*/", start)
            if end == -1:
                self.setCurrentBlockState(1)
                self.setFormat(start, len(text) - start, self.comment)
                break
            self.setFormat(start, end - start + 2, self.comment)
            start = text.find("/*", end + 2)


class _SyncProgress(QObject):
    progress = Signal(int, int, str)


class RulesPage(QWidget):
    def __init__(self, ctx, parent=None):
        super().__init__(parent)
        self.setObjectName("Page")
        self.ctx = ctx
        self.current = None  # (Path, read_only)
        self.dirty = False

        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(16)
        root.addLayout(page_header(
            "YARA rules",
            "Built-in rules always load. Your own rules and synced rule sets live in the YEMU data folder."))

        splitter = QSplitter()
        splitter.setChildrenCollapsible(False)
        root.addWidget(splitter, 1)

        # left: rule files
        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Filter rule files")
        self.filter.setClearButtonEnabled(True)
        self.filter.textChanged.connect(self._apply_filter)
        ll.addWidget(self.filter)
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.itemClicked.connect(self._open_item)
        ll.addWidget(self.tree, 1)
        new_btn = button("New rule", "plus")
        new_btn.clicked.connect(self._new_rule)
        ll.addWidget(new_btn)
        splitter.addWidget(left)

        # right: editor
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        head = QHBoxLayout()
        self.file_label = label("Select a rule file", "SectionTitle")
        head.addWidget(self.file_label, 1)
        self.validate_btn = button("Validate", "check")
        self.validate_btn.clicked.connect(self._validate)
        self.save_btn = button("Save", "save", "Primary")
        self.save_btn.clicked.connect(self._save)
        head.addWidget(self.validate_btn)
        head.addWidget(self.save_btn)
        rl.addLayout(head)
        self.editor = QPlainTextEdit()
        self.editor.setObjectName("Code")
        self.editor.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.editor.setTabStopDistance(28)
        self.highlighter = YaraHighlighter(self.editor.document(), theme.is_dark(ctx.config["ui"]["theme"]))
        self.editor.textChanged.connect(self._mark_dirty)
        rl.addWidget(self.editor, 1)
        self.status = label("", "Muted", wrap=True)
        rl.addWidget(self.status)
        splitter.addWidget(right)
        splitter.setSizes([280, 720])

        # bottom: sync
        sync, sl = card(horizontal=True)
        sl.addWidget(label("Sync from GitHub", "SectionTitle"))
        self.repo = QLineEdit(ctx.config["rules"]["repo_url"])
        self.branch = QLineEdit(ctx.config["rules"]["branch"])
        self.branch.setMaximumWidth(120)
        self.sync_btn = button("Sync", "download")
        self.sync_btn.clicked.connect(self._sync)
        self.sync_bar = QProgressBar()
        self.sync_bar.setFixedHeight(8)
        self.sync_bar.setMaximumWidth(160)
        self.sync_bar.hide()
        sl.addWidget(self.repo, 1)
        sl.addWidget(self.branch)
        sl.addWidget(self.sync_bar)
        sl.addWidget(self.sync_btn)
        root.addWidget(sync)

        self._progress = _SyncProgress()
        self._progress.progress.connect(self._on_sync_progress)
        self._set_editable(False)
        self.refresh()

    # --- files ---
    def _custom_dir(self):
        d = paths.synced_rules_dir() / "custom"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def refresh(self):
        self.tree.clear()
        groups = [
            ("Built-in (read-only)", [paths.BUILTIN_RULES_FILE], True, paths.BUILTIN_RULES_FILE.parent),
            ("My rules", sorted(self._custom_dir().glob("*.yar*")), False, self._custom_dir()),
        ]
        synced_root = paths.synced_rules_dir()
        synced = sorted(p for p in synced_root.rglob("*") if p.suffix in (".yar", ".yara")
                        and self._custom_dir() not in p.parents)
        groups.append((f"Synced ({len(synced)})", synced, False, synced_root))
        for title, files, ro, base in groups:
            top = QTreeWidgetItem([title])
            f = top.font(0)
            f.setBold(True)
            top.setFont(0, f)
            top.setFlags(Qt.ItemIsEnabled)
            for p in files:
                child = QTreeWidgetItem([str(p.relative_to(base)) if base in p.parents else p.name])
                child.setData(0, Qt.UserRole, (str(p), ro))
                child.setIcon(0, theme.icon("rules", "#98a2b3", 14))
                top.addChild(child)
            self.tree.addTopLevelItem(top)
            top.setExpanded(len(files) < 60)
        self._apply_filter(self.filter.text())

    def _apply_filter(self, text):
        text = text.lower()
        for i in range(self.tree.topLevelItemCount()):
            top = self.tree.topLevelItem(i)
            for j in range(top.childCount()):
                child = top.child(j)
                child.setHidden(bool(text) and text not in child.text(0).lower())
            if text:
                top.setExpanded(True)

    def _confirm_discard(self):
        if not self.dirty:
            return True
        return QMessageBox.question(self, "Unsaved changes", "Discard unsaved changes to this rule?") == QMessageBox.Yes

    def _open_item(self, item):
        data = item.data(0, Qt.UserRole)
        if not data or not self._confirm_discard():
            return
        path, ro = Path(data[0]), data[1]
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            self.status.setText(f"Could not open {path}: {e}")
            return
        self.current = (path, ro)
        self.editor.blockSignals(True)
        self.editor.setPlainText(text)
        self.editor.blockSignals(False)
        self.dirty = False
        self.file_label.setText(path.name + ("  (read-only)" if ro else ""))
        self._set_editable(not ro)
        self.validate_btn.setEnabled(True)
        self.status.setText(str(path))

    def _set_editable(self, editable):
        self.editor.setReadOnly(not editable)
        self.save_btn.setEnabled(editable)
        self.validate_btn.setEnabled(self.current is not None)

    def _mark_dirty(self):
        if self.current and not self.current[1] and not self.dirty:
            self.dirty = True
            self.file_label.setText(self.current[0].name + "  •")

    def _new_rule(self):
        if not self._confirm_discard():
            return
        name, ok = QInputDialog.getText(self, "New rule", "File name:", text="my_rule.yar")
        if not ok or not name.strip():
            return
        name = re.sub(r"[^A-Za-z0-9_.-]", "_", name.strip())
        if not name.endswith((".yar", ".yara")):
            name += ".yar"
        path = self._custom_dir() / name
        if path.exists():
            QMessageBox.warning(self, "YEMU", f"{name} already exists.")
            return
        stem = re.sub(r"\W", "_", path.stem)
        path.write_text(
            f'rule {stem}\n{{\n    meta:\n        description = "Describe what this detects"\n'
            f'    strings:\n        $a = "suspicious string" nocase\n    condition:\n        $a\n}}\n', encoding="utf-8")
        self.refresh()
        self._select_path(path)

    def _select_path(self, path):
        for i in range(self.tree.topLevelItemCount()):
            top = self.tree.topLevelItem(i)
            for j in range(top.childCount()):
                child = top.child(j)
                data = child.data(0, Qt.UserRole)
                if data and Path(data[0]) == path:
                    self.tree.setCurrentItem(child)
                    self._open_item(child)
                    return

    def _compile_error(self):
        if yara is None:
            return "yara-python is not installed"
        try:
            yara.compile(source=self.editor.toPlainText())
            return None
        except yara.SyntaxError as e:
            return str(e)
        except Exception as e:  # yara.Error and friends
            return str(e)

    def _validate(self):
        err = self._compile_error()
        if err:
            self.status.setText(f"✕ {err}")
            self.status.setStyleSheet(f"color: {theme.VERDICT_COLORS['malicious']};")
        else:
            self.status.setText("✓ Rule compiles")
            self.status.setStyleSheet(f"color: {theme.VERDICT_COLORS['clean']};")

    def _save(self):
        if not self.current or self.current[1]:
            return
        err = self._compile_error()
        if err and QMessageBox.question(self, "Rule does not compile",
                                        f"{err}\n\nSave anyway? Rules that fail to compile are skipped during analysis.") != QMessageBox.Yes:
            return
        self.current[0].write_text(self.editor.toPlainText(), encoding="utf-8")
        self.dirty = False
        self.file_label.setText(self.current[0].name)
        self.status.setStyleSheet("")
        self.status.setText(f"Saved {self.current[0]}")

    # --- sync ---
    def _sync(self):
        from yemu.core.yara_sync import YaraRuleSync
        self.sync_btn.setEnabled(False)
        self.sync_bar.show()
        self.sync_bar.setValue(0)
        sync = YaraRuleSync(repo_url=self.repo.text().strip(), branch=self.branch.text().strip() or "master")

        def done(manifest):
            self.sync_btn.setEnabled(True)
            self.sync_bar.hide()
            count = manifest.get("rule_count", manifest.get("count", "")) if isinstance(manifest, dict) else ""
            self.status.setStyleSheet("")
            self.status.setText(f"Sync complete {count}".strip())
            self.refresh()

        def failed(e):
            self.sync_btn.setEnabled(True)
            self.sync_bar.hide()
            QMessageBox.warning(self, "YEMU", f"Rule sync failed: {e}")

        self.ctx.bridge.call_sync(sync.sync, self._progress.progress.emit, on_result=done, on_error=failed)

    def _on_sync_progress(self, current, total, _name):
        self.sync_bar.setRange(0, max(total, 1))
        self.sync_bar.setValue(current)
