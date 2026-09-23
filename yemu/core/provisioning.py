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
from yemu.core.vm_provisioner import VMProvisioner

LINUX_DISTROS = ("ubuntu", "debian")
TOOLS_CHECK = "command -v strace && command -v tcpdump && command -v yara && echo YEMU_TOOLS_OK"


class ProvisioningError(RuntimeError):
    pass


async def provision_vm(
    backend,
    vm_name,
    distro="ubuntu",
    ram_mb=2048,
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
        url = provisioner.CLOUD_IMAGES[distro]
        backing = await asyncio.to_thread(provisioner.download_file, url, None, download_progress)
        report("Generating cloud-init seed...", 0.36)
        spec.cloud_init_path = await asyncio.to_thread(
            provisioner.create_cloud_init_iso, vm_name, provisioner.get_default_user_data()
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
        report("Waiting for cloud-init to finish installing tools...")
        # run_command gives up after ~60s, so keep re-waiting while cloud-init is busy
        for _ in range(15):
            if await backend.run_command(vm_name, "cloud-init status --wait >/dev/null 2>&1; echo done") != "TIMEOUT":
                break
        if "YEMU_TOOLS_OK" not in await backend.run_command(vm_name, TOOLS_CHECK):
            report("Tools missing after cloud-init, installing with apt...")
            await backend.run_command(vm_name, "apt-get update && apt-get install -y strace tcpdump yara")
            # apt may outlive run_command's timeout; give it time to finish in the background
            for _ in range(20):
                if "YEMU_TOOLS_OK" in await backend.run_command(vm_name, TOOLS_CHECK):
                    break
                await asyncio.sleep(15)
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

    report(f"Taking '{snapshot_name}' snapshot...")
    if not await backend.create_snapshot(vm_name, snapshot_name, "Automated baseline"):
        raise ProvisioningError("Failed to take baseline snapshot.")
    report(f"{vm_name} is ready.", 1.0)
    return provisioner.guest_password
