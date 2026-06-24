from gi.repository import Gtk, Adw, Gio, GLib
from ui.dashboard import Dashboard
from ui.log_viewer import LogViewer
from ui.yara_editor import YaraEditor
from ui.report_view import ReportView
import os
import subprocess

class MainWindow(Adw.ApplicationWindow):
    def _on_analysis_selected(self, listbox, row):
        if not row:
            return
        analysis_id = row.analysis_id

        import asyncio
        import threading

        def load_details():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            details = loop.run_until_complete(self.db.get_analysis_details(analysis_id))
            events = loop.run_until_complete(self.db.get_analysis_events(analysis_id))
            GLib.idle_add(self._display_analysis_details, details, events)

        threading.Thread(target=load_details, daemon=True).start()

    def _display_analysis_details(self, details, events):
        if not details:
            return

        import json
        yara_matches = json.loads(details['yara_matches']) if details['yara_matches'] else []

        self.dashboard.update_data(
            details['threat_score'] or 0,
            len(yara_matches),
            0, # TODO: IOC count
            events=events
        )
        self.report_view.update_report(details, events)
        self.stack.set_visible_child_name("dashboard")

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
            run_pcap = self.pcap_switch.get_active()

            vm_item = self.vm_dropdown.get_selected_item()
            snap_item = self.snapshot_dropdown.get_selected_item()

            vm_name = vm_item.get_string() if vm_item else None
            snap_name = snap_item.get_string() if snap_item else None

            self._start_analysis(file_path, vm_name, snap_name, run_gui, run_pcap)
        dialog.destroy()

    def _start_analysis(self, filename, vm_name, snap_name, run_gui, run_pcap):
        if hasattr(self, "_analysis_running") and self._analysis_running:
            self._append_log("Analysis already in progress. Please wait.", "WARN")
            return

        self._analysis_running = True
        self.upload_btn.set_sensitive(False)
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
                run_gui=run_gui,
                run_pcap=run_pcap
            ))
            GLib.idle_add(self._on_analysis_complete)

        threading.Thread(target=run_async, daemon=True).start()

    def _on_analysis_complete(self):
        self._analysis_running = False
        self._validate_submit()
        self._append_log("Analysis complete. Check the dashboard for results.", "INFO")
        self._update_recent_analyses()

    def _update_recent_analyses(self):
        import asyncio
        import threading

        def fetch_analyses():
            if not hasattr(self.db, 'conn'):
                return
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            analyses = loop.run_until_complete(self.db.get_recent_analyses())
            GLib.idle_add(self._populate_analysis_list, analyses)

        threading.Thread(target=fetch_analyses, daemon=True).start()

    def _populate_analysis_list(self, analyses):
        # Clear current list
        while True:
            row = self.analysis_list.get_first_child()
            if not row:
                break
            self.analysis_list.remove(row)

        for analysis in analyses:
            row = Adw.ActionRow(title=analysis['filename'])
            row.set_subtitle(f"{analysis['verdict'] or 'unknown'} - Score: {analysis['threat_score'] or 0}")
            row.analysis_id = analysis['id']
            self.analysis_list.append(row)

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
            self._append_log(f"Error listing VMs: {e}. Falling back to Mock Mode.", "CRITICAL")
            if not isinstance(self.orchestrator.vm_manager, MockVMManager):
                from core.vm_manager import MockVMManager
                self.orchestrator.vm_manager = MockVMManager(ui_callback=self._append_log)
                vms = [""] + sorted(self.orchestrator.vm_manager.list_vms())
                self.vm_dropdown.set_model(Gtk.StringList.new(vms))

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
        if hasattr(self, "_analysis_running") and self._analysis_running:
            self.upload_btn.set_sensitive(False)
            return

        vm_selected = False
        snap_selected = False

        vm_item = self.vm_dropdown.get_selected_item()
        if vm_item and vm_item.get_string():
            vm_selected = True

        snap_item = self.snapshot_dropdown.get_selected_item()
        if snap_item and snap_item.get_string():
            snap_selected = True

        self.upload_btn.set_sensitive(vm_selected and snap_selected)

    def _check_group_permissions(self):
        import grp
        import os
        try:
            username = os.getlogin()
            groups = [g.gr_name for g in grp.getgrall() if username in g.gr_mem]
            # Also check primary group
            import pwd
            primary_group_id = pwd.getpwnam(username).pw_gid
            groups.append(grp.getgrgid(primary_group_id).gr_name)

            missing = []
            if 'libvirt' not in groups: missing.append('libvirt')
            if 'kvm' not in groups: missing.append('kvm')

            if missing:
                msg = f"User '{username}' is missing groups: {', '.join(missing)}. " \
                      f"Please run 'sudo usermod -aG libvirt,kvm $USER' and re-login."
                self._append_log(msg, "CRITICAL")
                return False
            return True
        except Exception as e:
            self._append_log(f"Failed to check group permissions: {e}", "WARN")
            return True # Assume OK if check fails

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

        pcap_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)
        pcap_box.set_valign(Gtk.Align.CENTER)
        pcap_label = Gtk.Label(label="Packet Level Info")
        self.pcap_switch = Gtk.CheckButton()
        pcap_box.append(pcap_label)
        pcap_box.append(self.pcap_switch)
        upload_box.append(pcap_box)

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

        label = Gtk.Label(label="RECENT ANALYSES")
        label.add_css_class("caption")
        sidebar.append(label)

        self.analysis_list = Gtk.ListBox()
        self.analysis_list.add_css_class("navigation-sidebar")
        self.analysis_list.connect("row-selected", self._on_analysis_selected)

        scrolled_sidebar = Gtk.ScrolledWindow()
        scrolled_sidebar.set_vexpand(True)
        scrolled_sidebar.set_child(self.analysis_list)
        sidebar.append(scrolled_sidebar)

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
        from core.vm_manager import VMManager, MockVMManager
        import threading
        import asyncio

        self.db = Database()

        # Check permissions
        if not self._check_group_permissions():
            vm_mgr = MockVMManager(ui_callback=self._append_log)
            self._append_log("Starting in Mock Mode due to missing permissions.", "WARN")
        else:
            vm_mgr = VMManager(ui_callback=self._append_log)

        self.orchestrator = Orchestrator(self.db, vm_manager=vm_mgr, ui_callback=self._append_log)

        # Initial populations and validation
        self._update_vm_list()
        self._validate_submit()

        def init_db():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self.db.connect())
            GLib.idle_add(self._update_recent_analyses)

        threading.Thread(target=init_db, daemon=True).start()

        # Stack Switcher in Header
        switcher = Gtk.StackSwitcher()
        switcher.set_stack(self.stack)
        self.header.set_title_widget(switcher)
