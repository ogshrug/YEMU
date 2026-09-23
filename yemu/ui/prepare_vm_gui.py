import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, GLib, Gio
import asyncio
import threading
import logging

from yemu.core.vm_provisioner import VMProvisioner
from yemu.core.provisioning import provision_vm
from yemu.core.vm_backend import create_backend
from yemu import config as yemu_config
from yemu import paths


class VMPrepareWindow(Gtk.Window):
    def __init__(self, parent=None, backend=None, runner=None, on_finished=None, **kwargs):
        super().__init__(title="VM Preparation Tool", transient_for=parent, modal=True, **kwargs)
        self.set_default_size(600, 550)

        self.provisioner = VMProvisioner()
        self.backend = backend or create_backend("auto")
        self.runner = runner
        self.on_finished = on_finished
        self.analysis_network = yemu_config.load()["network"]["name"]
        self.logger = logging.getLogger("VMPrepare")

        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=20)
        main_box.set_margin_start(20)
        main_box.set_margin_end(20)
        main_box.set_margin_top(20)
        main_box.set_margin_bottom(20)
        self.set_child(main_box)

        group = Adw.PreferencesGroup(title="VM Settings")
        main_box.append(group)

        self.name_entry = Adw.EntryRow(title="VM Name")
        self.name_entry.set_text("ubuntu-clean")
        group.add(self.name_entry)

        distros = ["ubuntu", "debian"] + (["windows"] if self.backend.name == "libvirt" else [])
        model = Gtk.StringList(strings=distros)
        self.distro_combo = Gtk.DropDown(model=model)
        distro_row = Adw.ActionRow(title="Distribution")
        distro_row.add_suffix(self.distro_combo)
        group.add(distro_row)

        self.ram_adj = Gtk.Adjustment(value=2048, lower=1024, upper=16384, step_increment=1024)
        self.ram_spin = Gtk.SpinButton(adjustment=self.ram_adj, numeric=True)
        ram_row = Adw.ActionRow(title="RAM (MiB)")
        ram_row.add_suffix(self.ram_spin)
        group.add(ram_row)

        self.cpu_adj = Gtk.Adjustment(value=2, lower=1, upper=16, step_increment=1)
        self.cpu_spin = Gtk.SpinButton(adjustment=self.cpu_adj, numeric=True)
        cpu_row = Adw.ActionRow(title="CPU Cores")
        cpu_row.add_suffix(self.cpu_spin)
        group.add(cpu_row)

        self.disk_adj = Gtk.Adjustment(value=20, lower=10, upper=500, step_increment=10)
        self.disk_spin = Gtk.SpinButton(adjustment=self.disk_adj, numeric=True)
        disk_row = Adw.ActionRow(title="Disk Size (GiB)")
        disk_row.add_suffix(self.disk_spin)
        group.add(disk_row)

        self.progress_bar = Gtk.ProgressBar()
        self.progress_bar.set_show_text(True)
        main_box.append(self.progress_bar)

        actions_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        actions_box.set_halign(Gtk.Align.CENTER)
        main_box.append(actions_box)

        self.start_btn = Gtk.Button(label="Prepare VM")
        self.start_btn.add_css_class("suggested-action")
        self.start_btn.connect("clicked", self._on_start_clicked)
        actions_box.append(self.start_btn)

        self.expander = Gtk.Expander(label="Detailed Log")
        main_box.append(self.expander)

        scrolled = Gtk.ScrolledWindow()
        scrolled.set_min_content_height(200)
        self.log_text = Gtk.TextView(editable=False, cursor_visible=False)
        scrolled.set_child(self.log_text)
        self.expander.set_child(scrolled)

    def _append_log(self, text):
        buffer = self.log_text.get_buffer()
        buffer.insert_at_cursor(text + "\n")
        mark = buffer.get_insert()
        self.log_text.scroll_to_mark(mark, 0.0, True, 0.5, 0.5)

    def _on_start_clicked(self, btn):
        self.start_btn.set_sensitive(False)
        self.start_btn.set_label("Running...")
        vm_name = self.name_entry.get_text()
        selected = self.distro_combo.get_selected_item()
        distro = selected.get_string() if selected else "ubuntu"
        ram = int(self.ram_spin.get_value())
        cpu = int(self.cpu_spin.get_value())
        disk_size = int(self.disk_spin.get_value())
        threading.Thread(
            target=self._run_preparation,
            args=(vm_name, distro, ram, cpu, disk_size),
            daemon=True
        ).start()

    def _run_preparation(self, vm_name, distro, ram, cpu, disk_size):
        def progress(msg, fraction):
            if msg:
                GLib.idle_add(self._append_log, msg)
            if fraction is not None:
                GLib.idle_add(self.progress_bar.set_fraction, fraction)

        def on_done(password, error):
            if error:
                GLib.idle_add(self._append_log, f"ERROR: {error}")
                self.logger.error(f"Preparation failed: {error}")
            else:
                GLib.idle_add(self._append_log, "VM Preparation COMPLETED SUCCESSFULLY.")
                GLib.idle_add(self._append_log, f"Guest console password: {password}")
            GLib.idle_add(self.start_btn.set_sensitive, True)
            GLib.idle_add(self.start_btn.set_label, "Prepare VM")
            if self.on_finished:
                GLib.idle_add(self.on_finished)

        coro = provision_vm(
            self.backend, vm_name, distro=distro, ram_mb=ram, cpus=cpu, disk_gb=disk_size,
            analysis_network=self.analysis_network, progress=progress, provisioner=self.provisioner)
        if self.runner:
            self.runner.submit(coro, on_done=on_done)
        else:
            try:
                on_done(asyncio.run(coro), None)
            except Exception as e:
                on_done(None, e)


def main():
    app = Adw.Application(application_id="io.github.ogshrug.YEMU.PrepareVM")

    def on_activate(app):
        win = VMPrepareWindow(application=app)
        win.present()

    app.connect("activate", on_activate)
    app.run()


if __name__ == "__main__":
    main()
