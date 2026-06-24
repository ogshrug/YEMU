import logging
import asyncio
import os
import subprocess
import json
import base64
import tempfile
import shutil

try:
    import libvirt
except ImportError:
    libvirt = None

class VMManager:
    def __init__(self, ui_callback=None):
        self.logger = logging.getLogger(__name__)
        self.ui_callback = ui_callback
        self._conn = None
        # Fix for libguestfs kernel access errors
        os.environ["LIBGUESTFS_BACKEND"] = "direct"

    def _notify_ui(self, msg, severity="INFO"):
        if self.ui_callback:
            self.ui_callback(msg, severity)

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

    async def ensure_network(self, network_name="malware-analysis"):
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
            xml = f"""
            <network>
              <name>{network_name}</name>
              <bridge name='virbr-malware' stp='on' delay='0'/>
              <ip address='192.168.100.1' netmask='255.255.255.0'>
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

    async def define_vm(self, xml, vm_name):
        conn = self._get_conn()
        self._remove_existing_domain(vm_name)
        try:
            conn.defineXML(xml)
            return True
        except libvirt.libvirtError as e:
            self.logger.error(f"Failed to define VM: {e}")
            return False

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

class MockVMManager:
    def __init__(self, ui_callback=None):
        self.logger = logging.getLogger(__name__)
        self.ui_callback = ui_callback

    def _notify_ui(self, msg, severity="INFO"):
        if self.ui_callback:
            self.ui_callback(msg, severity)

    def list_vms(self):
        return ["mock-ubuntu", "mock-windows"]

    def list_snapshots(self, vm_name):
        return ["clean-baseline", "infected-state"]

    async def ensure_network(self, network_name="malware-analysis"):
        return True

    async def create_disk(self, disk_path, size_gb, backing_file=None):
        return disk_path

    async def define_vm(self, xml, vm_name):
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

    async def run_command(self, vm_name, command, shell="/bin/sh"):
        if "strace" in command:
            return "execve('/bin/ls', ['ls'], 0x7ffd989c8d30) = 0\nopenat(AT_FDCWD, '.', O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 3"
        if "yara" in command and "/proc" in command:
            return """
suspicious_process [malware,stealer] /proc/1234/mem
description: "Matched a suspicious pattern in memory"
author: "MalSandbox"
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

    async def revert_to_snapshot(self, vm_name, snapshot_name="clean-baseline"):
        return True

    async def open_gui(self, vm_name):
        self.logger.info(f"Mock: Opening GUI for {vm_name}")
        return True

    async def pull_file(self, vm_name, guest_path, local_path):
        return True
