.PHONY: install install-system run test sync-rules doctor clean

install-system:
	sudo apt update && sudo apt install -y qemu-kvm qemu-utils libvirt-daemon-system libvirt-clients \
		virt-manager virt-viewer libguestfs-tools genisoimage \
		python3-gi python3-gi-cairo gir1.2-gtk-4.0 gir1.2-adw-1 \
		libgtksourceview-5-dev python3-libvirt strace tcpdump yara

install:
	pip install -e ".[linux,dev]"

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
