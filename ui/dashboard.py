try:
    from gi.repository import Gtk, Adw
except ImportError:
    Gtk = None

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
        self.score_card.get_last_child().set_label(str(score or 0))
        self.yara_card.get_last_child().set_label(str(yara_count or 0))
        self.ioc_card.get_last_child().set_label(str(ioc_count or 0))

        self._populate_events(events or [])

    MAX_VISIBLE_EVENTS = 100

    def _populate_events(self, events):
        from gi.repository import Adw

        for lb in [self.proc_tree, self.net_view, self.file_view, self.yara_view]:
            while True:
                row = lb.get_first_child()
                if not row: break
                lb.remove(row)

        if not events:
            return

        events = events[:self.MAX_VISIBLE_EVENTS]

        processes = {}
        root_pids = []

        for ev in events:
            details = ev['details']
            if not isinstance(details, dict):
                continue
            ev_type = ev['event_type']

            if ev_type == 'process':
                pid = str(details.get('pid', ''))
                ppid = str(details.get('ppid', ''))

                if pid not in processes:
                    processes[pid] = {'details': details, 'children': []}
                else:
                    if details.get('action') == 'execute' or processes[pid]['details'].get('process_name') == 'unknown':
                        processes[pid]['details'].update(details)

                if ppid not in ("unknown", "None", "0", ""):
                    if ppid not in processes:
                        processes[ppid] = {'details': {'process_name': 'unknown', 'pid': ppid}, 'children': []}
                    if pid not in processes[ppid]['children']:
                        processes[ppid]['children'].append(pid)
                elif pid not in root_pids:
                    root_pids.append(pid)

        def add_proc_row(pid, depth=0):
            proc = processes.get(pid)
            if not proc: return
            det = proc['details']

            row = Adw.ActionRow()
            indent = "  " * depth
            name = det.get('process_name', 'unknown')
            action = det.get('action', '')
            row.set_title(f"{indent}PID {pid}: {name} ({action})")
            row.set_subtitle(f"{indent}Path: {det.get('path', 'N/A')}")
            self.proc_tree.append(row)

            for child_pid in proc['children']:
                add_proc_row(child_pid, depth + 1)

        for root_pid in root_pids:
            add_proc_row(root_pid)

        for ev in events:
            details = ev['details']
            if not isinstance(details, dict):
                continue
            ev_type = ev['event_type']

            if ev_type == 'yara':
                row = Adw.ExpanderRow()
                rule = details.get('rule', 'unknown')
                source = details.get('source', 'unknown').upper()

                row.set_title(f"[{source}] Rule: {rule}")

                pid = details.get('pid', 'N/A')
                proc = details.get('process_name', 'unknown')
                path = details.get('path', details.get('exe_path', '[unreadable]'))
                row.set_subtitle(f"PID: {pid} | Process: {proc}")

                tags = details.get('tags', [])
                meta = details.get('meta', {})
                desc = meta.get('description', 'N/A')

                info_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
                info_box.set_margin_start(15)
                info_box.set_margin_end(15)
                info_box.set_margin_top(10)
                info_box.set_margin_bottom(10)

                info_box.append(Gtk.Label(label=f"Full Path: {path}", xalign=0))
                info_box.append(Gtk.Label(label=f"Tags: {', '.join(tags) if tags else 'none'}", xalign=0))
                info_box.append(Gtk.Label(label=f"Description: {desc}", xalign=0))

                strings = details.get('strings', [])
                if strings:
                    info_box.append(Gtk.Label(label="Matched Strings:", xalign=0))
                    for s in strings[:20]:
                        if isinstance(s, dict):
                            offset = s.get('offset', '0x0')
                            identifier = s.get('identifier', '$?')
                            data = s.get('data', '')
                            printable = s.get('printable', '')
                        else:
                            offset = getattr(s, 'offset', '0x0')
                            identifier = getattr(s, 'identifier', '$?')
                            data = getattr(s, 'data', '')
                            printable = getattr(s, 'printable', '')

                        s_label = Gtk.Label(label=f"  {offset}:{identifier}: {data} ({printable})", xalign=0)
                        s_label.add_css_class("dim-label")
                        info_box.append(s_label)

                row.add_row(info_box)
                self.yara_view.append(row)
                continue

            row = Adw.ActionRow()
            if ev_type == 'process':
                continue
            elif ev_type == 'network':
                row.set_title(f"{details.get('dst_ip', 'N/A')}:{details.get('dst_port', 'N/A')}")
                row.set_subtitle(details.get('syscall', 'connect'))
                self.net_view.append(row)
            elif ev_type == 'file':
                path = details.get('path')
                if not path and details.get('fd'):
                    path = f"File Descriptor: {details.get('fd')}"
                row.set_title(f"{details.get('action', 'unknown').upper()}: {path or 'N/A'}")
                row.set_subtitle(details.get('syscall', ''))
                self.file_view.append(row)
