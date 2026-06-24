try:
    from gi.repository import Gtk, GLib, Adw
except ImportError:
    Gtk = None

import os
from pathlib import Path
import threading
import json
from core.yara_sync import YaraRuleSync

class YaraEditor(Gtk.Box):
    def __init__(self, **kwargs):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=10, **kwargs)
        self.set_margin_start(20)
        self.set_margin_end(20)
        self.set_margin_top(20)
        self.set_margin_bottom(20)

        self.rules_dir = Path("rules/yara-rules")
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        self.current_file = None

        # Sync UI
        sync_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        sync_box.set_margin_bottom(10)
        self.append(sync_box)

        sync_box.append(Gtk.Label(label="Repo URL:"))
        self.repo_entry = Gtk.Entry(text="https://github.com/Yara-Rules/rules")
        self.repo_entry.set_hexpand(True)
        sync_box.append(self.repo_entry)

        sync_box.append(Gtk.Label(label="Branch:"))
        self.branch_entry = Gtk.Entry(text="master")
        self.branch_entry.set_width_chars(10)
        sync_box.append(self.branch_entry)

        self.sync_btn = Gtk.Button(label="Sync Rules")
        self.sync_btn.connect("clicked", self._on_sync_clicked)
        sync_box.append(self.sync_btn)

        self.sync_progress = Gtk.ProgressBar()
        self.sync_progress.set_visible(False)
        self.sync_progress.set_hexpand(True)

        self.last_sync_label = Gtk.Label(label="Last sync: Never")
        self.last_sync_label.add_css_class("caption")

        info_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        info_box.append(self.sync_progress)
        info_box.append(self.last_sync_label)
        self.append(info_box)

        # Layout: Sidebar (file list) + Editor
        paned = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        paned.set_wide_handle(True)
        self.append(paned)

        # Sidebar
        sidebar = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        sidebar.set_size_request(250, -1)
        paned.set_start_child(sidebar)

        sidebar.append(Gtk.Label(label="RULES"))
        self.file_list = Gtk.ListBox()
        self.file_list.connect("row-selected", self._on_file_selected)

        scrolled_list = Gtk.ScrolledWindow()
        scrolled_list.set_vexpand(True)
        scrolled_list.set_child(self.file_list)
        sidebar.append(scrolled_list)

        new_btn = Gtk.Button(label="New Rule")
        new_btn.connect("clicked", self._on_new_rule)
        sidebar.append(new_btn)

        # Editor Area
        editor_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        paned.set_end_child(editor_box)

        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        editor_box.append(header)

        self.filename_entry = Gtk.Entry(placeholder_text="rule_name.yar")
        self.filename_entry.set_hexpand(True)
        header.append(self.filename_entry)

        save_btn = Gtk.Button(label="Save Rule")
        save_btn.add_css_class("suggested-action")
        save_btn.connect("clicked", self._on_save_rule)
        header.append(save_btn)

        scrolled_editor = Gtk.ScrolledWindow()
        scrolled_editor.set_vexpand(True)
        editor_box.append(scrolled_editor)

        self.text_view = Gtk.TextView()
        self.text_view.set_monospace(True)
        scrolled_editor.set_child(self.text_view)

        self.status_label = Gtk.Label(label="Ready")
        editor_box.append(self.status_label)

        self._load_manifest()
        self._refresh_file_list()

    def _load_manifest(self):
        manifest_path = self.rules_dir / ".sync_manifest.json"
        if manifest_path.exists():
            try:
                with manifest_path.open('r') as f:
                    data = json.load(f)
                    ts = data.get('timestamp', 'Unknown')
                    count = data.get('file_count', 0)
                    skipped = len(data.get('skipped_files', []))
                    self.last_sync_label.set_label(f"Last sync: {ts}. {count} rules synced, {skipped} skipped.")
            except Exception as e:
                self._log_message(f"Failed to load sync manifest: {e}", "WARN")

    def _refresh_file_list(self):
        while True:
            row = self.file_list.get_first_child()
            if not row: break
            self.file_list.remove(row)

        for file_path in sorted(self.rules_dir.rglob("*")):
            if file_path.is_file() and (file_path.suffix in [".yar", ".yara"]) and not file_path.name.startswith("."):
                rel_path = str(file_path.relative_to(self.rules_dir))
                row = Adw.ActionRow(title=rel_path)
                self.file_list.append(row)

    def _on_file_selected(self, listbox, row):
        if not row: return
        rel_path = row.get_title()
        self.current_file = rel_path
        self.filename_entry.set_text(rel_path)

        path = self.rules_dir / rel_path
        import threading
        def run_load():
            try:
                with path.open("r", errors='ignore') as f:
                    content = f.read()
                    GLib.idle_add(self._display_file, content, rel_path)
            except Exception as e:
                GLib.idle_add(self.status_label.set_label, f"Failed to load {rel_path}: {e}")
        threading.Thread(target=run_load, daemon=True).start()

    def _display_file(self, content, rel_path):
        self.text_view.get_buffer().set_text(content)
        self.status_label.set_label(f"Loaded {rel_path}")

    def _on_new_rule(self, btn):
        self.current_file = None
        self.filename_entry.set_text("")
        self.text_view.get_buffer().set_text("")
        self.status_label.set_label("New rule")

    def _on_save_rule(self, btn):
        filename = self.filename_entry.get_text()
        if not filename:
            self.status_label.set_label("Error: Filename required")
            return
        if not (filename.endswith(".yar") or filename.endswith(".yara")):
            filename += ".yar"

        buffer = self.text_view.get_buffer()
        start, end = buffer.get_bounds()
        content = buffer.get_text(start, end, True)

        path = self.rules_dir / filename
        path.parent.mkdir(parents=True, exist_ok=True)

        import threading
        def run_save():
            try:
                with path.open("w") as f:
                    f.write(content)
                GLib.idle_add(self._on_save_complete, filename)
            except Exception as e:
                GLib.idle_add(self.status_label.set_label, f"Save failed: {e}")
        threading.Thread(target=run_save, daemon=True).start()

    def _on_save_complete(self, filename):
        self.status_label.set_label(f"Saved {filename}")
        self._refresh_file_list()

    def _on_sync_clicked(self, btn):
        repo_url = self.repo_entry.get_text()
        branch = self.branch_entry.get_text()

        self.sync_btn.set_sensitive(False)
        self.sync_progress.set_visible(True)
        self.sync_progress.set_fraction(0)

        threading.Thread(target=self._run_sync, args=(repo_url, branch), daemon=True).start()

    def _run_sync(self, repo_url, branch):
        def progress_cb(current, total, filename):
            fraction = current / total if total > 0 else 0
            GLib.idle_add(self.sync_progress.set_fraction, fraction)
            msg = f"Syncing: {filename}"
            GLib.idle_add(self._log_message, msg, "INFO")

        try:
            sync_tool = YaraRuleSync(repo_url=repo_url, branch=branch, rules_dir=self.rules_dir)
            manifest = sync_tool.sync(progress_callback=progress_cb)

            GLib.idle_add(self._on_sync_complete, manifest)
        except Exception as e:
            GLib.idle_add(self._on_sync_error, str(e))

    def _on_sync_complete(self, manifest):
        self.sync_btn.set_sensitive(True)
        self.sync_progress.set_visible(False)
        self._load_manifest()
        self._refresh_file_list()
        self._log_message("YARA rules sync completed successfully.", "INFO")

    def _on_sync_error(self, error_msg):
        self.sync_btn.set_sensitive(True)
        self.sync_progress.set_visible(False)
        self._log_message(f"YARA rules sync failed: {error_msg}", "ERROR")

    def _log_message(self, msg, level):
        # Try to find the main window and its log viewer
        window = self.get_root()
        if window and hasattr(window, "_append_log"):
            window._append_log(msg, level)
        else:
            print(f"[{level}] {msg}")
