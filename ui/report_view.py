try:
    from gi.repository import Gtk, Adw
except ImportError:
    Gtk = None

class ReportView(Gtk.Box):
    def __init__(self, **kwargs):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=10, **kwargs)
        self.set_margin_start(20)
        self.set_margin_end(20)
        self.set_margin_top(20)
        self.set_margin_bottom(20)

        self.current_details = None
        self.current_events = None

        self.title_label = Gtk.Label(label="Analysis Report Details")
        self.title_label.add_css_class("h2")
        self.append(self.title_label)

        # IOC Table
        self.ioc_list = Gtk.ListBox()
        self.ioc_list.set_selection_mode(Gtk.SelectionMode.NONE)

        scrolled = Gtk.ScrolledWindow()
        scrolled.set_vexpand(True)
        scrolled.set_child(self.ioc_list)
        self.append(scrolled)

        self.export_btn = Gtk.Button(label="Export to PDF")
        self.export_btn.set_sensitive(False)
        self.export_btn.connect("clicked", self._on_export_pdf)
        self.append(self.export_btn)

    def update_report(self, details, events):
        if not details:
            self.title_label.set_label("No report data available")
            self.export_btn.set_sensitive(False)
            return

        self.current_details = details
        self.current_events = events or []
        self.title_label.set_label(f"Report: {details.get('filename', 'unknown')}")
        self.export_btn.set_sensitive(True)

        # Clear list
        while True:
            row = self.ioc_list.get_first_child()
            if not row: break
            self.ioc_list.remove(row)

        # Add some key info as "IOCs"
        import json
        yara_matches_raw = details.get('yara_matches')
        yara_matches = json.loads(yara_matches_raw) if yara_matches_raw else []

        has_content = False
        for match in yara_matches:
            has_content = True
            if isinstance(match, dict):
                rule = match.get('rule', 'unknown')
                pid = match.get('pid', 'N/A')
                proc = match.get('process_name', 'unknown')
                val = f"Rule: {rule} (PID: {pid}, Proc: {proc})"
                self.add_ioc("YARA", val)
            else:
                self.add_ioc("YARA", str(match))

        for ev in self.current_events:
            det = json.loads(ev['details']) if isinstance(ev['details'], str) else ev['details']
            if ev['event_type'] == 'network':
                has_content = True
                self.add_ioc("Network", f"{det.get('dst_ip')}:{det.get('dst_port')}")

        if not has_content:
            row = Adw.ActionRow(title="No IOCs detected during analysis.", subtitle="Clean")
            self.ioc_list.append(row)

    def add_ioc(self, ioc_type, value):
        row = Adw.ActionRow(title=value, subtitle=ioc_type)
        self.ioc_list.append(row)

    def _on_export_pdf(self, btn):
        if not self.current_details: return

        root = self.get_root()
        if not root: return

        dialog = Gtk.FileChooserDialog(
            title="Save PDF Report",
            parent=root,
            action=Gtk.FileChooserAction.SAVE,
        )
        dialog.add_button("_Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("_Save", Gtk.ResponseType.ACCEPT)
        dialog.set_current_name(f"report_{self.current_details['id']}.pdf")

        dialog.connect("response", self._on_save_response)
        dialog.present()

    def _on_save_response(self, dialog, response):
        if response == Gtk.ResponseType.ACCEPT:
            path = dialog.get_file().get_path()
            if not path.endswith(".pdf"): path += ".pdf"

            import threading
            from gi.repository import GLib

            def run_export():
                try:
                    from core.report_generator import PDFGenerator
                    gen = PDFGenerator(path)
                    gen.generate(self.current_details, self.current_events)
                    GLib.idle_add(self._show_export_result, f"PDF saved to {path}", False)
                except Exception as e:
                    GLib.idle_add(self._show_export_result, f"Failed to export PDF: {e}", True)

            threading.Thread(target=run_export, daemon=True).start()
        dialog.destroy()

    def _show_export_result(self, message, is_error):
        root = self.get_root()
        if not root:
            return
        toast = Adw.Toast(title=message)
        toast.set_timeout(5)
        if hasattr(root, 'add_toast'):
            root.add_toast(toast)
        else:
            print(f"Export result: {message}")
