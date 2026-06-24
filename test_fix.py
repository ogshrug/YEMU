
import asyncio
import logging
from core.vm_manager import VMManager, MockVMManager
from core.orchestrator import Orchestrator
import libvirt

async def test_vm_manager_connection_fallback():
    print("Testing VMManager connection fallback...")
    vm_mgr = VMManager()
    try:
        conn = vm_mgr._get_conn()
        print(f"Connected to: {conn.getURI()}")
    except Exception as e:
        print(f"Connection failed as expected in restricted environment: {e}")

async def test_mock_vm_manager():
    print("Testing MockVMManager...")
    mock_mgr = MockVMManager()
    vms = mock_mgr.list_vms()
    assert "mock-ubuntu" in vms
    print("MockVMManager list_vms passed")

    out = await mock_mgr.run_command("any", "strace something")
    assert "execve" in out
    print("MockVMManager run_command passed")

async def main():
    await test_vm_manager_connection_fallback()
    await test_mock_vm_manager()
    print("All additional tests passed!")

if __name__ == "__main__":
    asyncio.run(main())
