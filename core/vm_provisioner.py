import requests
import os
import logging
import yaml
import tempfile
import subprocess

class VMProvisioner:
    """
    Handles downloading ISOs/Cloud images and providing templates for VM creation.
    """
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

    def __init__(self, download_dir="assets/iso"):
        self.download_dir = download_dir
        self.logger = logging.getLogger(__name__)
        os.makedirs(self.download_dir, exist_ok=True)

    def download_file(self, url, filename=None):
        if not filename:
            filename = os.path.basename(url)
        target_path = os.path.join(self.download_dir, filename)

        if os.path.exists(target_path):
            self.logger.info(f"File {filename} already exists.")
            return target_path

        self.logger.info(f"Downloading {url} to {target_path}...")
        try:
            response = requests.get(url, stream=True, timeout=30)
            response.raise_for_status()
            with open(target_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            self.logger.info(f"Downloaded {target_path}")
        except Exception as e:
            self.logger.error(f"Download failed: {e}")
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

    def create_cloud_init_iso(self, vm_name, user_data_content):
        """Creates a cloud-init ISO containing user-data and meta-data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            user_data_path = os.path.join(tmpdir, "user-data")
            meta_data_path = os.path.join(tmpdir, "meta-data")

            with open(user_data_path, "w") as f:
                f.write("#cloud-config\n" + user_data_content)

            with open(meta_data_path, "w") as f:
                f.write(f"instance-id: {vm_name}\nlocal-hostname: {vm_name}\n")

            iso_path = os.path.join(self.download_dir, f"{vm_name}-cloud-init.iso")
            cmd = ["genisoimage", "-output", iso_path, "-volid", "cidata", "-joliet", "-rock", user_data_path, meta_data_path]
            subprocess.run(cmd, check=True, capture_output=True)
            return iso_path

    def create_windows_auto_iso(self, vm_name):
        """Creates an ISO for Windows containing Autounattend.xml."""
        xml_content = self.generate_autounattend_xml()
        with tempfile.TemporaryDirectory() as tmpdir:
            xml_path = os.path.join(tmpdir, "Autounattend.xml")
            with open(xml_path, "w") as f:
                f.write(xml_content)

            iso_path = os.path.join(self.download_dir, f"{vm_name}-windows-auto.iso")
            cmd = ["genisoimage", "-output", iso_path, "-volid", "OEMDRIVERS", "-joliet", "-rock", xml_path]
            subprocess.run(cmd, check=True, capture_output=True)
            return iso_path

    def get_default_user_data(self):
        """Standard cloud-init configuration for the sandbox."""
        config = {
            "package_update": True,
            "package_upgrade": True,
            "packages": ["qemu-guest-agent", "strace", "tcpdump", "curl"],
            "password": "analysis-password",
            "chpasswd": {"expire": False},
            "ssh_pwauth": True,
            "runcmd": [
                ["systemctl", "enable", "--now", "qemu-guest-agent"],
            ]
        }
        return yaml.dump(config)

    def generate_autounattend_xml(self):
        """Improved Autounattend.xml for Windows automated install with partitioning and drivers."""
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
                    <Path>E:\amd64\w11</Path>
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
                            <Value>analysis-password</Value>
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
                    <Value>analysis-password</Value>
                    <PlainText>true</PlainText>
                </Password>
                <Enabled>true</Enabled>
                <Username>analyst</Username>
            </AutoLogon>
            <FirstLogonCommands>
                <SynchronousCommand wcm:action="add">
                    <CommandLine>powershell -ExecutionPolicy Bypass -Command "Get-ChildItem -Path D:\, E:\, F:\ -Include virtio-win-guest-tools.exe -Recurse | ForEach-Object { & $_ /S }"</CommandLine>
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
"""

    def get_libvirt_xml(self, vm_name, ram_mb=2048, cpu_count=2, disk_path=None, iso_path=None, cloud_init_path=None, virtio_win_path=None, windows_auto_path=None):
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
            <type arch='x86_64' machine='pc-q35-4.2'>hvm</type>
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
              <source network='malware-analysis'/>
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
