from gi.repository import Gtk, Adw, Gio, GLib
from ui.dashboard import Dashboard
from ui.log_viewer import LogViewer
from ui.yara_editor import YaraEditor
from ui.report_view import ReportView
import os
import subprocess

class MainWindow(Adw.ApplicationWindow):
    def _on_submit_clicked(self, btn):
        dialog = Gtk.FileChooserDialog(
            title="Select File for Analysis",
            parent=self,
            action=Gtk.FileChooserAction.OPEN,
        )
        dialog.add_button("_Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("_Open", Gtk.ResponseType.ACCEPT)

        dialog.connect("response", self._on_file_chooser_response)
        dialog.present()

    def _on_file_chooser_response(self, dialog, response):
        if response == Gtk.ResponseType.ACCEPT:
            file_path = dialog.get_file().get_path()
            run_gui = self.gui_switch.get_active()

            vm_item = self.vm_dropdown.get_selected_item()
            snap_item = self.snapshot_dropdown.get_selected_item()

            vm_name = vm_item.get_string() if vm_item else None
            snap_name = snap_item.get_string() if snap_item else None

            self._start_analysis(file_path, vm_name, snap_name, run_gui)
        dialog.destroy()

    def _start_analysis(self, filename, vm_name, snap_name, run_gui):
        self._append_log(f"Submitting {filename} for analysis on {vm_name} ({snap_name})...", "INFO")

        import threading
        import asyncio
        def run_async():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self.orchestrator.run_analysis(
                filename,
                guest_os=vm_name,
                snapshot_name=snap_name,
                run_gui=run_gui
            ))
            GLib.idle_add(self._on_analysis_complete)

        threading.Thread(target=run_async, daemon=True).start()

    def _on_analysis_complete(self):
        self._append_log("Analysis complete. Check the dashboard for results.", "INFO")
        # In a real app, we'd pull this from the DB
        self.dashboard.update_data(87, 4, 12)

    def _on_prepare_vm_clicked(self, btn):
        script = os.path.join(os.path.dirname(__file__), "prepare_vm.sh")
        subprocess.Popen(["bash", script], cwd=os.path.dirname(script))

    def _append_log(self, msg, sev):
        GLib.idle_add(self.log_viewer.append_log, msg, sev)

    def _update_vm_list(self):
        try:
            vms = self.orchestrator.vm_manager.list_vms()
            vms = [""] + sorted(vms)
            self.vm_dropdown.set_model(Gtk.StringList.new(vms))
        except Exception as e:
            self._append_log(f"Error listing VMs: {e}", "CRITICAL")

    def _on_vm_selected(self, dropdown, pspec):
        selected_item = dropdown.get_selected_item()
        if selected_item:
            vm_name = selected_item.get_string()
            if vm_name:
                try:
                    snapshots = self.orchestrator.vm_manager.list_snapshots(vm_name)
                    snapshots = [""] + sorted(snapshots)
                    self.snapshot_dropdown.set_model(Gtk.StringList.new(snapshots))
                except Exception as e:
                    self._append_log(f"Error listing snapshots: {e}", "CRITICAL")
                    self.snapshot_dropdown.set_model(Gtk.StringList.new([""]))
            else:
                self.snapshot_dropdown.set_model(Gtk.StringList.new([""]))
        self._validate_submit()

    def _on_snapshot_selected(self, dropdown, pspec):
        self._validate_submit()

    def _validate_submit(self):
        vm_selected = False
        snap_selected = False

        vm_item = self.vm_dropdown.get_selected_item()
        if vm_item and vm_item.get_string():
            vm_selected = True

        snap_item = self.snapshot_dropdown.get_selected_item()
        if snap_item and snap_item.get_string():
            snap_selected = True

        self.upload_btn.set_sensitive(vm_selected and snap_selected)

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

        gui_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)
        gui_box.set_valign(Gtk.Align.CENTER)
        gui_label = Gtk.Label(label="Run with GUI")
        self.gui_switch = Gtk.CheckButton()
        gui_box.append(gui_label)
        gui_box.append(self.gui_switch)
        upload_box.append(gui_box)

        self.prepare_btn = Gtk.Button(label="Prepare New VM")
        self.prepare_btn.connect("clicked", self._on_prepare_vm_clicked)
        upload_box.append(self.prepare_btn)

        self.main_box.append(upload_box)

        # VM/Snapshot Selection
        selection_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        selection_box.set_halign(Gtk.Align.CENTER)
        selection_box.set_margin_bottom(10)

        selection_box.append(Gtk.Label(label="Target VM:"))
        self.vm_dropdown = Gtk.DropDown()
        self.vm_dropdown.connect("notify::selected", self._on_vm_selected)
        selection_box.append(self.vm_dropdown)

        selection_box.append(Gtk.Label(label="Snapshot:"))
        self.snapshot_dropdown = Gtk.DropDown()
        self.snapshot_dropdown.connect("notify::selected", self._on_snapshot_selected)
        selection_box.append(self.snapshot_dropdown)

        self.main_box.append(selection_box)

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
        import threading
        import asyncio

        self.db = Database()
        self.orchestrator = Orchestrator(self.db, ui_callback=self._append_log)

        # Initial populations and validation
        self._update_vm_list()
        self._validate_submit()

        def init_db():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self.db.connect())

        threading.Thread(target=init_db, daemon=True).start()

        # Stack Switcher in Header
        switcher = Gtk.StackSwitcher()
        switcher.set_stack(self.stack)
        self.header.set_title_widget(switcher)
