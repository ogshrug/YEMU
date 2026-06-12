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
        self.append(self.notebook)

        self.proc_tree = Gtk.Label(label="Process Tree details will appear here")
        self.notebook.append_page(self.proc_tree, Gtk.Label(label="Process Tree"))

        self.net_view = Gtk.Label(label="Network activity details will appear here")
        self.notebook.append_page(self.net_view, Gtk.Label(label="Network"))

        self.file_view = Gtk.Label(label="File event details will appear here")
        self.notebook.append_page(self.file_view, Gtk.Label(label="File Events"))

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

    def update_data(self, score, yara_count, ioc_count):
        self.score_card.get_last_child().set_label(str(score))
        self.yara_card.get_last_child().set_label(str(yara_count))
        self.ioc_card.get_last_child().set_label(str(ioc_count))
