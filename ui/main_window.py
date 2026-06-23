from gi.repository import Gtk, Adw, Gio, GLib
from ui.dashboard import Dashboard
from ui.log_viewer import LogViewer
from ui.yara_editor import YaraEditor
from ui.report_view import ReportView
import os

class MainWindow(Adw.ApplicationWindow):
    def _on_submit_clicked(self, btn):
        # In a real scenario, this would be a file chooser dialog
        # For now, let's assume a default path or a simple file existence check
        filename = "malicious_sample.elf"
        if not os.path.exists(filename):
            # Create a dummy file if it doesn't exist for testing purposes
            with open(filename, "wb") as f:
                f.write(b"\x7fELF" + os.urandom(100))

        self._append_log(f"Submitting {filename}...", "INFO")

        import threading
        import asyncio
        def run_async():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self.orchestrator.run_analysis(filename))
            GLib.idle_add(self._on_analysis_complete)

        threading.Thread(target=run_async, daemon=True).start()

    def _on_analysis_complete(self):
        self._append_log("Analysis complete. Check the dashboard for results.", "INFO")
        # In a real app, we'd pull this from the DB
        self.dashboard.update_data(87, 4, 12)

    def _append_log(self, msg, sev):
        GLib.idle_add(self.log_viewer.append_log, msg, sev)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.set_title("Malware Sandbox")
        self.set_default_size(1200, 900)

        # Main Layout
        self.main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.set_content(self.main_box)

        # Header
        self.header = Adw.HeaderBar()
        self.main_box.append(self.header)

        # File Drop/Upload
        upload_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        upload_box.set_margin_start(10)
        upload_box.set_margin_end(10)
        upload_box.set_margin_top(10)
        upload_box.set_margin_bottom(10)
        upload_box.set_halign(Gtk.Align.CENTER)

        self.upload_btn = Gtk.Button(label="Submit File for Analysis")
        self.upload_btn.add_css_class("suggested-action")
        self.upload_btn.connect("clicked", self._on_submit_clicked)
        upload_box.append(self.upload_btn)

        self.main_box.append(upload_box)

        # Paned view (Sidebar + Content)
        paned = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        paned.set_wide_handle(True)
        self.main_box.append(paned)

        # Sidebar
        sidebar = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        sidebar.set_size_request(250, -1)
        sidebar.add_css_class("sidebar")
        paned.set_start_child(sidebar)

        sidebar.append(Gtk.Label(label="RECENT ANALYSES"))
        self.analysis_list = Gtk.ListBox()
        sidebar.append(self.analysis_list)

        # Content Stack
        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.SLIDE_LEFT_RIGHT)
        paned.set_end_child(self.stack)

        self.dashboard = Dashboard()
        self.stack.add_titled(self.dashboard, "dashboard", "Dashboard")

        self.yara_editor = YaraEditor()
        self.stack.add_titled(self.yara_editor, "yara", "YARA Rules")

        self.report_view = ReportView()
        self.stack.add_titled(self.report_view, "reports", "Reports")

        # Bottom: Log Viewer
        self.log_viewer = LogViewer()
        self.main_box.append(self.log_viewer)

        # Database and Orchestrator
        from storage.db import Database
        from core.orchestrator import Orchestrator
        import asyncio

        self.db = Database()
        # Note: In a real app, wrap the async init in a way GTK likes
        GLib.idle_add(lambda: asyncio.run(self.db.connect()))

        self.orchestrator = Orchestrator(self.db, ui_callback=self._append_log)

        # Stack Switcher in Header
        switcher = Gtk.StackSwitcher()
        switcher.set_stack(self.stack)
        self.header.set_title_widget(switcher)
