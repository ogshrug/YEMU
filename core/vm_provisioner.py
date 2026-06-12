import requests
import os
import logging

class VMProvisioner:
    """
    Handles downloading ISOs and providing templates for VM creation.
    """
    DISTROS = {
        "ubuntu": "https://releases.ubuntu.com/24.04/ubuntu-24.04.1-live-server-amd64.iso",
        "mint": "https://mirrors.layeronline.com/linuxmint/stable/22/linuxmint-22-cinnamon-64bit.iso",
        "alpine": "https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-virt-3.20.3-x86_64.iso",
        "windows": "https://software-static.download.prss.microsoft.com/db_releases/Windows_11_Enterprise_Evaluation_Multi.iso" # Example
    }

    def __init__(self, download_dir="assets/iso"):
        self.download_dir = download_dir
        self.logger = logging.getLogger(__name__)
        os.makedirs(self.download_dir, exist_ok=True)

    def download_iso(self, distro_name):
        if distro_name not in self.DISTROS:
            raise ValueError(f"Unknown distro: {distro_name}")

        url = self.DISTROS[distro_name]
        filename = os.path.basename(url)
        target_path = os.path.join(self.download_dir, filename)

        if os.path.exists(target_path):
            self.logger.info(f"ISO {filename} already exists.")
            return target_path

        self.logger.info(f"Downloading {distro_name} ISO from {url}...")
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

    def get_libvirt_xml(self, distro_name, vm_name, ram_mb=2048, cpu_count=2):
        if distro_name not in self.DISTROS:
            raise ValueError(f"Unknown distro: {distro_name}")

        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        if not vm_name or any(c not in allowed for c in vm_name):
            raise ValueError("vm_name contains invalid characters")

        # Template for creating a new VM
        return f"""
        <domain type='kvm'>
          <name>{vm_name}</name>
          <memory unit='MiB'>{ram_mb}</memory>
          <vcpu placement='static'>{cpu_count}</vcpu>
          <os>
            <type arch='x86_64' machine='pc-q35-4.2'>hvm</type>
          </os>
          <devices>
            <disk type='file' device='disk'>
              <driver name='qemu' type='qcow2'/>
              <source file='/var/lib/libvirt/images/{vm_name}.qcow2'/>
              <target dev='vda' bus='virtio'/>
            </disk>
            <interface type='network'>
              <source network='malware-analysis'/>
              <model type='virtio'/>
            </interface>
            <console type='pty'>
              <target type='serial' port='0'/>
            </console>
          </devices>
        </domain>
        """
