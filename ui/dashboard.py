from gi.repository import Gtk, Adw

class Dashboard(Gtk.Box):
    def __init__(self, **kwargs):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=20, **kwargs)
        self.set_margin_top(20)
        self.set_margin_bottom(20)
        self.set_margin_start(20)
        self.set_margin_end(20)

        # Summary Cards
        cards_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=20)
        cards_box.set_halign(Gtk.Align.CENTER)
        self.append(cards_box)

        self.score_card = self._create_card("Threat Score", "0", "suggested")
        self.yara_card = self._create_card("YARA Matches", "0", "warning")
        self.ioc_card = self._create_card("IOCs Found", "0", "error")

        cards_box.append(self.score_card)
        cards_box.append(self.yara_card)
        cards_box.append(self.ioc_card)

        # Tabs for details
        self.notebook = Gtk.Notebook()
        self.notebook.set_vexpand(True)
        self.append(self.notebook)

        self.proc_tree = Gtk.ListBox()
        self.notebook.append_page(self._create_scrolled(self.proc_tree), Gtk.Label(label="Process Tree"))

        self.net_view = Gtk.ListBox()
        self.notebook.append_page(self._create_scrolled(self.net_view), Gtk.Label(label="Network"))

        self.file_view = Gtk.ListBox()
        self.notebook.append_page(self._create_scrolled(self.file_view), Gtk.Label(label="File Events"))

        self.yara_view = Gtk.ListBox()
        self.notebook.append_page(self._create_scrolled(self.yara_view), Gtk.Label(label="YARA Matches"))

    def _create_scrolled(self, widget):
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_vexpand(True)
        scrolled.set_child(widget)
        return scrolled

    def _create_card(self, title, value, style):
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        card.add_css_class("card")
        card.set_size_request(200, 150)

        t_label = Gtk.Label(label=title)
        v_label = Gtk.Label(label=value)
        v_label.add_css_class("h1")

        card.append(t_label)
        card.append(v_label)
        return card

    def update_data(self, score, yara_count, ioc_count, events=None):
        self.score_card.get_last_child().set_label(str(score))
        self.yara_card.get_last_child().set_label(str(yara_count))
        self.ioc_card.get_last_child().set_label(str(ioc_count))

        if events:
            self._populate_events(events)

    def _populate_events(self, events):
        import json
        from gi.repository import Adw

        # Clear lists
        for lb in [self.proc_tree, self.net_view, self.file_view, self.yara_view]:
            while True:
                row = lb.get_first_child()
                if not row: break
                lb.remove(row)

        for ev in events:
            details = json.loads(ev['details']) if isinstance(ev['details'], str) else ev['details']
            ev_type = ev['event_type']

            if ev_type == 'yara':
                row = Adw.ExpanderRow()
                rule = details.get('rule', 'unknown')
                pid = details.get('pid', 'N/A')
                proc = details.get('process_name', 'unknown')
                path = details.get('path', details.get('exe_path', '[unreadable]'))

                row.set_title(f"[MATCH] Rule: {rule}  |  PID: {pid}  |  Process: {proc}")
                row.set_subtitle(f"Path: {path}")

                # Add tags and meta
                tags = details.get('tags', [])
                meta = details.get('meta', {})
                desc = meta.get('description', 'N/A')

                info_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
                info_box.set_margin_start(15)
                info_box.set_margin_end(15)
                info_box.set_margin_top(10)
                info_box.set_margin_bottom(10)

                info_box.append(Gtk.Label(label=f"Tags: {', '.join(tags) if tags else 'none'}", xalign=0))
                info_box.append(Gtk.Label(label=f"Description: {desc}", xalign=0))

                # Add strings
                strings = details.get('strings', [])
                if strings:
                    info_box.append(Gtk.Label(label="Matched Strings:", xalign=0))
                    for s in strings:
                        s_label = Gtk.Label(label=f"  {s['offset']}:{s['identifier']}: {s['data']} ({s.get('printable', '')})", xalign=0)
                        s_label.add_css_class("dim-label")
                        info_box.append(s_label)

                row.add_row(info_box)
                self.yara_view.append(row)
                continue

            row = Adw.ActionRow()
            if ev_type == 'process':
                row.set_title(f"PID {details.get('pid', 'N/A')}: {details.get('action', 'unknown')}")
                row.set_subtitle(details.get('path', ''))
                self.proc_tree.append(row)
            elif ev_type == 'network':
                row.set_title(f"{details.get('dst_ip', 'N/A')}:{details.get('dst_port', 'N/A')}")
                row.set_subtitle(details.get('syscall', 'connect'))
                self.net_view.append(row)
            elif ev_type == 'file':
                row.set_title(f"{details.get('action', 'unknown').upper()}: {details.get('path', 'N/A')}")
                row.set_subtitle(details.get('syscall', ''))
                self.file_view.append(row)
