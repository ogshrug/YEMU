.PHONY: install run clean

install:
	sudo apt update && sudo apt install -y qemu-kvm libvirt-daemon-system virt-manager \
		python3-gi python3-gi-cairo gir1.2-gtk-4.0 gir1.2-adw-1 \
		libgtksourceview-5-dev strace tcpdump yara
	pip install -r requirements.txt

run:
	python main.py

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	rm -rf assets/reports/*
