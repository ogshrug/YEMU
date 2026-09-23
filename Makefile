.PHONY: install install-system run test sync-rules doctor clean

install-system:
	sudo apt update && sudo apt install -y qemu-kvm qemu-utils libvirt-daemon-system libvirt-clients \
		virt-manager virt-viewer libguestfs-tools genisoimage \
		python3-libvirt strace tcpdump yara libegl1 libxkbcommon-x11-0 libxcb-cursor0

install:
	pip install -e ".[linux,gui,dev]"

run:
	yemu gui

test:
	pytest -q

sync-rules:
	yemu sync-rules

doctor:
	yemu doctor

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	rm -rf build dist *.egg-info
