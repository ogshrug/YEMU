"""
Backend-neutral VM preparation, shared by the GUI (Prepare New VM) and `yemu vm create`.

Flow: download a cloud image -> build a cloud-init seed -> create an overlay disk ->
boot on the NAT provisioning network so the guest can install its tools ->
move the VM to the isolated analysis network -> snapshot "clean-baseline".
"""

import asyncio
import os
import zipfile

from yemu.core.vm_backend import PROVISION_NETWORK, VMSpec
from yemu.core.vm_catalog import CATALOG, DONE_MARKER
from yemu.core.vm_provisioner import VMProvisioner

LINUX_DISTROS = tuple(CATALOG)
TOOLS_CHECK = "command -v strace && command -v tcpdump && command -v yara && echo YEMU_TOOLS_OK"
DESKTOP_CHECK = "systemctl is-active display-manager lightdm 2>/dev/null | grep -qx active && echo YEMU_DESKTOP_OK"
PROVISION_TIMEOUT = 2 * 3600  # a desktop install under software emulation can take an hour or more


class ProvisioningError(RuntimeError):
    pass


async def provision_vm(
    backend,
    vm_name,
    distro="ubuntu",
    desktop=True,
    ram_mb=3072,
    cpus=2,
    disk_gb=20,
    analysis_network="malware-analysis",
    snapshot_name="clean-baseline",
    agent_timeout=900,
    progress=None,
    provisioner=None,
):
    """
    Create a ready-to-analyse VM. progress(message, fraction) is called as it goes
    (fraction is None for pure log lines). Returns the guest console password.
    """
    provisioner = provisioner or VMProvisioner()

    def report(msg, fraction=None):
        if progress:
            progress(msg, fraction)

    if distro not in LINUX_DISTROS and not (distro == "windows" and backend.name == "libvirt"):
        raise ProvisioningError(f"Distro '{distro}' is not supported on the {backend.name} backend")

    report(f"Preparing {vm_name} ({distro}) on the {backend.name} backend...", 0.02)
    report(f"Ensuring isolated network '{analysis_network}'...")
    if not await backend.ensure_network(analysis_network, nat=False):
        raise ProvisioningError("Failed to ensure isolated network.")
    report(f"Ensuring provisioning network '{PROVISION_NETWORK}' (NAT)...")
    if not await backend.ensure_network(PROVISION_NETWORK, nat=True):
        raise ProvisioningError("Failed to ensure provisioning network.")
    report("Networks ready.", 0.05)

    def download_progress(done, total):
        if total:
            report(None, 0.05 + 0.3 * done / total)

    spec = VMSpec(
        name=vm_name,
        disk_path=backend.vm_disk_path(vm_name),
        ram_mb=ram_mb,
        cpus=cpus,
        network=PROVISION_NETWORK,
        os_type="windows" if distro == "windows" else "linux",
    )
    backing = None
    procmon_path = None
    if distro in LINUX_DISTROS:
        report(f"Downloading {distro} cloud image (cached after the first run)...")
        url = CATALOG[distro].image_url
        backing = await asyncio.to_thread(provisioner.download_file, url, None, download_progress)
        report("Generating cloud-init seed...", 0.36)
        spec.cloud_init_path = await asyncio.to_thread(
            provisioner.create_cloud_init_iso, vm_name, provisioner.get_default_user_data(distro, desktop)
        )
    else:
        report("Downloading Windows ISO, VirtIO drivers and Procmon...")
        spec.iso_path = await asyncio.to_thread(provisioner.download_iso, "windows")
        spec.virtio_win_path = await asyncio.to_thread(provisioner.download_virtio_win)
        spec.windows_auto_path = await asyncio.to_thread(provisioner.create_windows_auto_iso, vm_name)
        procmon_zip = await asyncio.to_thread(provisioner.download_procmon)
        extract_dir = os.path.join(provisioner.download_dir, "procmon_tmp")
        with zipfile.ZipFile(procmon_zip) as zf:
            zf.extractall(extract_dir)
        procmon_path = os.path.join(extract_dir, "Procmon.exe")
    report("Downloads complete.", 0.4)

    report("Creating VM disk...")
    disk = await backend.create_disk(spec.disk_path, disk_gb, backing_file=backing)
    if not disk:
        raise ProvisioningError("Failed to create disk image.")
    spec.disk_path = disk
    if not await backend.define_vm(spec):
        raise ProvisioningError("Failed to define VM.")
    report("VM defined.", 0.45)

    report("Booting on the provisioning network (installing guest tools, 3-10 minutes)...")
    if not await backend.start_vm(vm_name):
        raise ProvisioningError("Failed to start VM.")
    if not await backend.wait_for_guest_agent(vm_name, timeout=agent_timeout):
        raise ProvisioningError("Guest agent timeout. Installation may have failed (check the VM console).")
    report("Guest agent is up.", 0.7)

    if procmon_path:
        report("Installing Process Monitor in the Windows guest...")
        await backend.inject_file_via_agent(vm_name, procmon_path, "C:\\Users\\analyst\\Desktop\\Procmon.exe")

    if distro in LINUX_DISTROS:
        what = "tools and the XFCE desktop" if desktop else "tools"
        report(f"Installing {what} in the guest (this takes a while; log: /var/log/yemu-provision.log)...")
        waited = 0
        while "done" not in await backend.run_command(vm_name, f"[ -f {DONE_MARKER} ] && echo done"):
            if waited >= PROVISION_TIMEOUT:
                raise ProvisioningError(f"The guest was still installing after {PROVISION_TIMEOUT // 60} minutes.")
            await asyncio.sleep(20)
            waited += 20
            if waited % 300 == 0:
                last = (await backend.run_command(vm_name, "tail -n 1 /var/log/yemu-provision.log")).strip()
                report(f"Still installing ({waited // 60} min): {last[:120]}")
        failed = (await backend.run_command(vm_name, f"cat {DONE_MARKER}.err 2>/dev/null")).strip()
        if failed:
            tail = (await backend.run_command(vm_name, "tail -n 15 /var/log/yemu-provision.log")).strip()
            raise ProvisioningError(f"Guest setup failed: {failed.splitlines()[0][:200]}\n{tail}")
        if "YEMU_TOOLS_OK" not in await backend.run_command(vm_name, TOOLS_CHECK):
            raise ProvisioningError("strace/tcpdump/yara could not be installed in the guest.")
    report("Guest tools installed.", 0.8)

    report(f"Moving VM onto isolated network '{analysis_network}'...")
    if not await backend.switch_network(vm_name, PROVISION_NETWORK, analysis_network):
        raise ProvisioningError("Failed to move VM onto the isolated network.")
    if not await backend.start_vm(vm_name):
        raise ProvisioningError("Failed to restart VM on the isolated network.")
    if not await backend.wait_for_guest_agent(vm_name, timeout=300):
        raise ProvisioningError("Guest agent timeout after network switch.")
    exposed = await backend.find_internet_facing_networks(vm_name)
    if exposed:
        raise ProvisioningError(f"VM is still internet-facing after the switch: {', '.join(exposed)}")
    report("VM is isolated.", 0.9)
    if distro in LINUX_DISTROS and desktop:
        report("Waiting for the desktop to start...")
        for _ in range(30):
            if "YEMU_DESKTOP_OK" in await backend.run_command(vm_name, DESKTOP_CHECK):
                break
            await asyncio.sleep(5)
        else:
            raise ProvisioningError("The desktop (lightdm) did not start after the reboot.")

    report(f"Taking '{snapshot_name}' snapshot...")
    if not await backend.create_snapshot(vm_name, snapshot_name, "Automated baseline"):
        raise ProvisioningError("Failed to take baseline snapshot.")
    report(f"{vm_name} is ready.", 1.0)
    return provisioner.guest_password
