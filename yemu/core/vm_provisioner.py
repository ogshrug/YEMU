import requests
import os
import logging
import yaml
import tempfile
import subprocess
import shutil
import secrets

from yemu import paths

class VMProvisioner:
    DISTROS = {
        "ubuntu": "https://releases.ubuntu.com/24.04/ubuntu-24.04.1-live-server-amd64.iso",
        "mint": "https://mirrors.layeronline.com/linuxmint/stable/22/linuxmint-22-cinnamon-64bit.iso",
        "alpine": "https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-virt-3.20.3-x86_64.iso",
        "windows": "https://software-static.download.prss.microsoft.com/db_releases/Windows_11_Enterprise_Evaluation_Multi.iso"
    }

    CLOUD_IMAGES = {
        "ubuntu": "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img",
        "debian": "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2",
    }

    VIRTIO_WIN_URL = "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/latest-virtio/virtio-win.iso"
    PROCMON_URL = "https://download.sysinternals.com/files/ProcessMonitor.zip"

    def __init__(self, download_dir=None):
        download_dir = str(download_dir or paths.images_dir())
        self.download_dir = download_dir
        self.logger = logging.getLogger(__name__)
        # Per-provisioner random guest password instead of a hard-coded one
        self.guest_password = secrets.token_urlsafe(12)

    def download_file(self, url, filename=None, progress_callback=None):
        if not filename:
            filename = os.path.basename(url)
        target_path = os.path.join(self.download_dir, filename)

        if os.path.exists(target_path):
            self.logger.info(f"File {filename} already exists.")
            return target_path

        # Download to .part and rename, so an interrupted download is never mistaken for a complete one
        part_path = target_path + ".part"
        self.logger.info(f"Downloading {url} to {target_path}...")
        try:
            with requests.get(url, stream=True, timeout=30) as response:
                response.raise_for_status()
                total = int(response.headers.get("content-length", 0))
                done = 0
                with open(part_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=1024 * 1024):
                        f.write(chunk)
                        done += len(chunk)
                        if progress_callback:
                            progress_callback(done, total)
            os.replace(part_path, target_path)
            self.logger.info(f"Downloaded {target_path}")
        except Exception as e:
            self.logger.error(f"Download failed: {e}")
            try:
                os.remove(part_path)
            except OSError:
                pass
            raise
        return target_path

    def download_iso(self, distro_name):
        if distro_name not in self.DISTROS:
            raise ValueError(f"Unknown distro: {distro_name}")
        return self.download_file(self.DISTROS[distro_name])

    def download_cloud_image(self, distro_name):
        if distro_name not in self.CLOUD_IMAGES:
            raise ValueError(f"Unknown cloud image distro: {distro_name}")
        return self.download_file(self.CLOUD_IMAGES[distro_name])

    def download_virtio_win(self):
        return self.download_file(self.VIRTIO_WIN_URL, "virtio-win.iso")

    def download_procmon(self):
        return self.download_file(self.PROCMON_URL, "ProcessMonitor.zip")

    @staticmethod
    def _find_mkisofs():
        for exe in ["genisoimage", "mkisofs", "xorrisofs"]:
            path = shutil.which(exe)
            if path:
                return path
        return None

    def _build_iso(self, files, volume_id, out_path):
        """
        Write a small Joliet + Rock Ridge ISO holding `files` ({name: bytes}).
        Uses genisoimage/mkisofs when installed, otherwise pure-Python pycdlib (Windows).
        """
        if os.path.exists(out_path):
            os.remove(out_path)
        mkisofs = self._find_mkisofs()
        if mkisofs:
            with tempfile.TemporaryDirectory() as tmpdir:
                file_paths = []
                for name, data in files.items():
                    fp = os.path.join(tmpdir, name)
                    with open(fp, "wb") as f:
                        f.write(data)
                    file_paths.append(fp)
                cmd = [mkisofs, "-output", out_path, "-volid", volume_id, "-joliet", "-rock", *file_paths]
                result = subprocess.run(cmd, check=False, capture_output=True)
                if result.returncode != 0:
                    stderr = result.stderr.decode(errors="replace")
                    raise RuntimeError(f"{os.path.basename(mkisofs)} failed (exit {result.returncode}): {stderr}")
        else:
            try:
                import pycdlib
            except ImportError:
                raise RuntimeError("No ISO tool found: install genisoimage (Linux) or `pip install pycdlib`")
            import io
            iso = pycdlib.PyCdlib()
            iso.new(interchange_level=3, joliet=3, rock_ridge="1.09", vol_ident=volume_id)
            for idx, (name, data) in enumerate(files.items()):
                iso9660_name = f"/F{idx}.;1"
                iso.add_fp(io.BytesIO(data), len(data), iso9660_name, rr_name=name, joliet_path=f"/{name}")
            iso.write(out_path)
            iso.close()
        if os.name != "nt":
            os.chmod(out_path, 0o644)
        return out_path

    def create_cloud_init_iso(self, vm_name, user_data_content):
        files = {
            "user-data": ("#cloud-config\n" + user_data_content).encode(),
            "meta-data": f"instance-id: {vm_name}\nlocal-hostname: {vm_name}\n".encode(),
        }
        out_path = os.path.join(str(paths.vm_storage_dir()), f"{vm_name}-cloud-init.iso")
        return self._build_iso(files, "cidata", out_path)

    def create_windows_auto_iso(self, vm_name):
        files = {"Autounattend.xml": self.generate_autounattend_xml().encode()}
        out_path = os.path.join(str(paths.vm_storage_dir()), f"{vm_name}-windows-auto.iso")
        return self._build_iso(files, "OEMDRIVERS", out_path)

    def get_default_user_data(self):
        config = {
            "package_update": True,
            # A full upgrade adds minutes and isn't needed for a throwaway analysis guest
            "package_upgrade": False,
            # yara must be installed now: the analysis network has no internet access
            "packages": ["qemu-guest-agent", "strace", "tcpdump", "curl", "yara"],
            "password": self.guest_password,
            "chpasswd": {"expire": False},
            "ssh_pwauth": False,
            "runcmd": [
                ["systemctl", "enable", "--now", "qemu-guest-agent"],
            ]
        }
        return yaml.dump(config)

    def generate_autounattend_xml(self):
        return """<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="windowsPE">
        <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <DiskConfiguration>
                <Disk wcm:action="add">
                    <DiskID>0</DiskID>
                    <WillWipeDisk>true</WillWipeDisk>
                    <CreatePartitions>
                        <CreatePartition wcm:action="add">
                            <Order>1</Order>
                            <Type>Primary</Type>
                            <Size>500</Size>
                        </CreatePartition>
                        <CreatePartition wcm:action="add">
                            <Order>2</Order>
                            <Type>Primary</Type>
                            <Extend>true</Extend>
                        </CreatePartition>
                    </CreatePartitions>
                    <ModifyPartitions>
                        <ModifyPartition wcm:action="add">
                            <Order>1</Order>
                            <PartitionID>1</PartitionID>
                            <Label>System</Label>
                            <Format>NTFS</Format>
                        </ModifyPartition>
                        <ModifyPartition wcm:action="add">
                            <Order>2</Order>
                            <PartitionID>2</PartitionID>
                            <Label>Windows</Label>
                            <Format>NTFS</Format>
                        </ModifyPartition>
                    </ModifyPartitions>
                </Disk>
            </DiskConfiguration>
            <ImageInstall>
                <OSImage>
                    <InstallTo>
                        <DiskID>0</DiskID>
                        <PartitionID>2</PartitionID>
                    </InstallTo>
                    <WillShowUI>OnError</WillShowUI>
                </OSImage>
            </ImageInstall>
            <UserData>
                <AcceptEula>true</AcceptEula>
                <FullName>Malware Analyst</FullName>
                <Organization>Sandbox</Organization>
            </UserData>
            <DriverPaths>
                <PathAndCredentials wcm:action="add">
                    <Path>E:\\amd64\\w11</Path>
                </PathAndCredentials>
            </DriverPaths>
        </component>
        <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <SetupUILanguage>
                <UILanguage>en-US</UILanguage>
            </SetupUILanguage>
            <InputLocale>en-US</InputLocale>
            <SystemLocale>en-US</SystemLocale>
            <UILanguage>en-US</UILanguage>
            <UserLocale>en-US</UserLocale>
        </component>
    </settings>
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <UserAccounts>
                <LocalAccounts>
                    <LocalAccount wcm:action="add">
                        <Password>
                            <Value>{password}</Value>
                            <PlainText>true</PlainText>
                        </Password>
                        <Description>Analyst Account</Description>
                        <DisplayName>Analyst</DisplayName>
                        <Group>Administrators</Group>
                        <Name>analyst</Name>
                    </LocalAccount>
                </LocalAccounts>
            </UserAccounts>
            <AutoLogon>
                <Password>
                    <Value>{password}</Value>
                    <PlainText>true</PlainText>
                </Password>
                <Enabled>true</Enabled>
                <Username>analyst</Username>
            </AutoLogon>
            <FirstLogonCommands>
                <SynchronousCommand wcm:action="add">
                    <CommandLine>powershell -ExecutionPolicy Bypass -Command "Get-ChildItem -Path D:\\, E:\\, F:\\ -Include virtio-win-guest-tools.exe -Recurse | ForEach-Object { & $_ /S }"</CommandLine>
                    <Description>Install VirtIO Guest Tools (includes Guest Agent)</Description>
                    <Order>1</Order>
                </SynchronousCommand>
            </FirstLogonCommands>
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
                <HideLocalAdministrationPage>true</HideLocalAdministrationPage>
                <HideOEMRegistrationPage>true</HideOEMRegistrationPage>
                <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
                <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
                <NetworkLocation>Work</NetworkLocation>
                <ProtectYourPC>3</ProtectYourPC>
            </OOBE>
        </component>
    </settings>
</unattend>
""".replace("{password}", self.guest_password)

    @classmethod
    def render_libvirt_xml(cls, spec):
        return cls.get_libvirt_xml(
            spec.name, spec.ram_mb, spec.cpus,
            disk_path=spec.disk_path, iso_path=spec.iso_path, cloud_init_path=spec.cloud_init_path,
            virtio_win_path=spec.virtio_win_path, windows_auto_path=spec.windows_auto_path,
            network_name=spec.network)

    @staticmethod
    def get_libvirt_xml(vm_name, ram_mb=2048, cpu_count=2, disk_path=None, iso_path=None, cloud_init_path=None, virtio_win_path=None, windows_auto_path=None, network_name="malware-analysis"):
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        if not vm_name or any(c not in allowed for c in vm_name):
            raise ValueError("vm_name contains invalid characters")

        devices_xml = f"""
            <disk type='file' device='disk'>
              <driver name='qemu' type='qcow2'/>
              <source file='{disk_path}'/>
              <target dev='vda' bus='virtio'/>
            </disk>
        """

        cdroms = []
        if iso_path: cdroms.append(iso_path)
        if cloud_init_path: cdroms.append(cloud_init_path)
        if virtio_win_path: cdroms.append(virtio_win_path)
        if windows_auto_path: cdroms.append(windows_auto_path)

        for i, path in enumerate(cdroms):
            dev = f"sd{chr(ord('a') + i)}"
            devices_xml += f"""
            <disk type='file' device='cdrom'>
              <driver name='qemu' type='raw'/>
              <source file='{path}'/>
              <target dev='{dev}' bus='sata'/>
              <readonly/>
            </disk>
            """

        return f"""
        <domain type='kvm'>
          <name>{vm_name}</name>
          <memory unit='MiB'>{ram_mb}</memory>
          <vcpu placement='static'>{cpu_count}</vcpu>
          <os>
            <type arch='x86_64' machine='q35'>hvm</type>
            <boot dev='hd'/>
            <boot dev='cdrom'/>
          </os>
          <features>
            <acpi/><apic/><pae/>
          </features>
          <cpu mode='host-passthrough'/>
          <devices>
            {devices_xml}
            <interface type='network'>
              <source network='{network_name}'/>
              <model type='virtio'/>
            </interface>
            <channel type='unix'>
              <target type='virtio' name='org.qemu.guest_agent.0'/>
            </channel>
            <console type='pty'>
              <target type='serial' port='0'/>
            </console>
            <input type='tablet' bus='usb'/>
            <graphics type='spice' autoport='yes'/>
            <video>
              <model type='qxl'/>
            </video>
          </devices>
        </domain>
        """
