from gi.repository import Gtk, Adw

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
        self.current_details = details
        self.current_events = events
        self.title_label.set_label(f"Report: {details['filename']}")
        self.export_btn.set_sensitive(True)

        # Clear list
        while True:
            row = self.ioc_list.get_first_child()
            if not row: break
            self.ioc_list.remove(row)

        # Add some key info as "IOCs"
        import json
        yara_matches = json.loads(details['yara_matches']) if details['yara_matches'] else []

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

        for ev in events:
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

        dialog = Gtk.FileChooserDialog(
            title="Save PDF Report",
            parent=self.get_root(),
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

            from core.report_generator import PDFGenerator
            gen = PDFGenerator(path)
            gen.generate(self.current_details, self.current_events)
        dialog.destroy()
