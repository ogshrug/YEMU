from gi.repository import Gtk

import os

class YaraEditor(Gtk.Box):
    def __init__(self, **kwargs):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=10, **kwargs)
        self.set_margin_start(20)
        self.set_margin_end(20)
        self.set_margin_top(20)
        self.set_margin_bottom(20)

        self.rules_dir = "rules"
        os.makedirs(self.rules_dir, exist_ok=True)
        self.current_file = None

        # Layout: Sidebar (file list) + Editor
        paned = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        paned.set_wide_handle(True)
        self.append(paned)

        # Sidebar
        sidebar = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        sidebar.set_size_request(200, -1)
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

        self._refresh_file_list()

    def _refresh_file_list(self):
        while True:
            row = self.file_list.get_first_child()
            if not row: break
            self.file_list.remove(row)

        for f in os.listdir(self.rules_dir):
            if f.endswith(".yar") or f.endswith(".yara"):
                from gi.repository import Adw
                row = Adw.ActionRow(title=f)
                self.file_list.append(row)

    def _on_file_selected(self, listbox, row):
        if not row: return
        filename = row.get_title()
        self.current_file = filename
        self.filename_entry.set_text(filename)

        path = os.path.join(self.rules_dir, filename)
        with open(path, "r") as f:
            self.text_view.get_buffer().set_text(f.read())
        self.status_label.set_label(f"Loaded {filename}")

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

        path = os.path.join(self.rules_dir, filename)
        try:
            with open(path, "w") as f:
                f.write(content)
            self.status_label.set_label(f"Saved {filename}")
            self._refresh_file_list()
        except Exception as e:
            self.status_label.set_label(f"Save failed: {e}")
