import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, GLib, Gio
import asyncio
import threading
import os
import sys
import logging
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from core.vm_provisioner import VMProvisioner
from core.vm_manager import VMManager

class VMPrepareWindow(Gtk.Window):
    def __init__(self, parent=None, **kwargs):
        super().__init__(title="VM Preparation Tool", transient_for=parent, modal=True, **kwargs)
        self.set_default_size(600, 550)

        self.provisioner = VMProvisioner()
        self.manager = VMManager()
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

        model = Gtk.StringList(strings=["ubuntu", "debian", "windows"])
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
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self._async_prepare(vm_name, distro, ram, cpu, disk_size))
        loop.close()
        GLib.idle_add(self.start_btn.set_sensitive, True)
        GLib.idle_add(self.start_btn.set_label, "Prepare VM")

    async def _async_prepare(self, vm_name, distro, ram, cpu, disk_size):
        GLib.idle_add(self._append_log, f"Starting preparation for {vm_name} ({distro})...")
        GLib.idle_add(self.progress_bar.set_fraction, 0.05)

        try:
            GLib.idle_add(self._append_log, "Ensuring isolated network exists...")
            if not await self.manager.ensure_network():
                raise RuntimeError("Failed to ensure isolated network.")
            GLib.idle_add(self.progress_bar.set_fraction, 0.1)

            GLib.idle_add(self._append_log, f"Downloading {distro} image and tools...")
            image_path = None
            cloud_init_path = None
            virtio_win_path = None
            windows_auto_path = None
            procmon_path = None

            if distro in ["ubuntu", "debian"]:
                image_path = self.provisioner.download_cloud_image(distro)
                GLib.idle_add(self._append_log, "Generating Cloud-Init configuration...")
                user_data = self.provisioner.get_default_user_data()
                cloud_init_path = self.provisioner.create_cloud_init_iso(vm_name, user_data)
            elif distro == "windows":
                image_path = self.provisioner.download_iso("windows")
                GLib.idle_add(self._append_log, "Downloading VirtIO drivers and Procmon...")
                virtio_win_path = self.provisioner.download_virtio_win()
                windows_auto_path = self.provisioner.create_windows_auto_iso(vm_name)
                procmon_zip = self.provisioner.download_procmon()
                with zipfile.ZipFile(procmon_zip, 'r') as zip_ref:
                    extract_dir = os.path.join(self.provisioner.download_dir, "procmon_tmp")
                    zip_ref.extractall(extract_dir)
                    procmon_path = os.path.join(extract_dir, "Procmon.exe")

            GLib.idle_add(self.progress_bar.set_fraction, 0.4)

            GLib.idle_add(self._append_log, "Creating VM disk image...")
            disk_path = f"/var/lib/libvirt/images/{vm_name}.qcow2"
            backing = os.path.abspath(image_path) if image_path and distro in ["ubuntu", "debian"] else None
            actual_disk_path = await self.manager.create_disk(disk_path, disk_size, backing_file=backing)
            if not actual_disk_path:
                raise RuntimeError("Failed to create disk image.")
            GLib.idle_add(self.progress_bar.set_fraction, 0.5)

            GLib.idle_add(self._append_log, "Defining VM in libvirt...")
            xml = self.provisioner.get_libvirt_xml(
                vm_name, ram, cpu,
                disk_path=actual_disk_path,
                cloud_init_path=cloud_init_path,
                virtio_win_path=virtio_win_path,
                windows_auto_path=windows_auto_path,
                iso_path=image_path if distro == "windows" else None
            )
            if not await self.manager.define_vm(xml, vm_name):
                raise RuntimeError("Failed to define VM.")
            GLib.idle_add(self.progress_bar.set_fraction, 0.6)

            GLib.idle_add(self._append_log, "Starting VM for installation and configuration...")
            if not await self.manager.start_vm(vm_name):
                raise RuntimeError("Failed to start VM.")

            GLib.idle_add(self._append_log, "Waiting for Guest Agent to become ready (may take 5-10 minutes)...")
            GLib.idle_add(self.progress_bar.set_fraction, 0.7)

            if not await self.manager.wait_for_guest_agent(vm_name, timeout=900):
                raise RuntimeError("Guest agent timeout. Installation may have failed.")

            if distro == "windows" and procmon_path:
                GLib.idle_add(self._append_log, "Installing Process Monitor in Windows guest...")
                await self.manager.stop_vm(vm_name)
                await self.manager.inject_file(vm_name, procmon_path, "C:\\Users\\analyst\\Desktop\\Procmon.exe")
                await self.manager.start_vm(vm_name)
                await self.manager.wait_for_guest_agent(vm_name)

            GLib.idle_add(self._append_log, "Verifying environment tools (strace, tcpdump)...")
            if distro in ["ubuntu", "debian"]:
                await self.manager.run_command(vm_name, "apt-get update && apt-get install -y strace tcpdump")

            GLib.idle_add(self._append_log, "Taking 'clean-baseline' snapshot...")
            GLib.idle_add(self.progress_bar.set_fraction, 0.9)
            if not await self.manager.create_snapshot(vm_name, "clean-baseline", "Automated baseline"):
                raise RuntimeError("Failed to take baseline snapshot.")

            GLib.idle_add(self.progress_bar.set_fraction, 1.0)
            GLib.idle_add(self._append_log, "VM Preparation COMPLETED SUCCESSFULLY.")

        except Exception as e:
            GLib.idle_add(self._append_log, f"ERROR: {str(e)}")
            self.logger.error(f"Preparation failed: {e}", exc_info=True)


def main():
    app = Adw.Application(application_id="org.gpcssi.vmprep")

    def on_activate(app):
        win = VMPrepareWindow(application=app)
        win.present()

    app.connect("activate", on_activate)
    app.run()


if __name__ == "__main__":
    main()
