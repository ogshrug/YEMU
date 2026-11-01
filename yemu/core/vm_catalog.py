"""
The base Linux VMs YEMU can build: the most popular distro of each family, all with the same
analyst account and an XFCE desktop that logs in by itself.
"""

import shlex
from dataclasses import dataclass

ANALYST = "analyst"  # the desktop account on every catalog VM; the console password is set per session
TOOLS = "qemu-guest-agent strace tcpdump yara"
AUTOLOGIN = (
    "mkdir -p /etc/lightdm/lightdm.conf.d && "
    f"printf '[Seat:*]\\nautologin-user={ANALYST}\\nautologin-session=xfce\\n' "
    ">/etc/lightdm/lightdm.conf.d/50-yemu-autologin.conf"
)


@dataclass(frozen=True)
class Distro:
    key: str
    label: str
    base: str
    image_url: str
    agent: str  # installs and starts the guest agent first, so YEMU can follow the rest
    tools: str
    desktop: str
    package_kinds: tuple[str, ...]  # samples the guest can install with its own package manager


CATALOG = {
    d.key: d
    for d in (
        Distro(
            key="ubuntu",
            label="Ubuntu 26.04 LTS",
            base="Debian",
            image_url="https://cloud-images.ubuntu.com/releases/26.04/release/ubuntu-26.04-server-cloudimg-amd64.img",
            agent="apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y qemu-guest-agent",
            tools=f"DEBIAN_FRONTEND=noninteractive apt-get install -y {TOOLS}",
            # recommends would pull in the whole GNOME session and gdm3 next to XFCE
            desktop="DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "
            "xubuntu-desktop-minimal xserver-xorg-input-all xfce4-terminal dbus-x11 && "
            "echo /usr/sbin/lightdm >/etc/X11/default-display-manager",
            package_kinds=("deb",),
        ),
        Distro(
            key="fedora",
            label="Fedora 44",
            base="Red Hat",
            image_url="https://dl.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/"
            "Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2",
            agent="dnf install -y qemu-guest-agent",
            tools=f"dnf install -y {TOOLS}",
            desktop="dnf install -y @xfce-desktop-environment lightdm",
            package_kinds=("rpm",),
        ),
        Distro(
            key="arch",
            label="Arch Linux",
            base="Arch",
            image_url="https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2",
            # a full upgrade first: installing on top of a stale image is a partial upgrade, which Arch breaks on
            agent="pacman-key --init && pacman-key --populate && pacman -Syu --noconfirm --needed qemu-guest-agent",
            tools=f"pacman -S --noconfirm --needed {TOOLS}",
            desktop="pacman -S --noconfirm --needed xorg-server xfce4 lightdm lightdm-gtk-greeter && "
            f"groupadd -rf autologin && gpasswd -a {ANALYST} autologin",
            package_kinds=("pkg",),
        ),
        Distro(
            key="opensuse",
            label="openSUSE Tumbleweed",
            base="SUSE",
            image_url="https://download.opensuse.org/tumbleweed/appliances/"
            "openSUSE-Tumbleweed-Minimal-VM.x86_64-Cloud.qcow2",
            agent="zypper --non-interactive --gpg-auto-import-keys refresh && "
            "zypper --non-interactive install qemu-guest-agent",
            tools=f"zypper --non-interactive install {TOOLS}",
            desktop="zypper --non-interactive install -t pattern xfce && zypper --non-interactive install lightdm && "
            "update-alternatives --set default-displaymanager /usr/lib/X11/displaymanagers/lightdm",
            package_kinds=("rpm",),
        ),
    )
}

DONE_MARKER = "/var/lib/yemu-provisioned"
# SELinux confines the guest agent (virt_qemu_ga_t): it could not read the provision log, trace the
# sample or read /proc, so YEMU would never see the guest. A throwaway analysis VM runs permissive.
PERMISSIVE = (
    "if command -v setenforce >/dev/null; then setenforce 0; "
    "sed -i 's/^SELINUX=.*/SELINUX=permissive/' /etc/selinux/config; fi; true"
)
# openSUSE ships the agent with guest-exec and the file calls blocked (FILTER_RPC_ARGS in
# /usr/etc/sysconfig/qemu-ga); an admin file in /etc overrides it. Restart so a running agent picks it up.
AGENT_ON = (
    "mkdir -p /etc/sysconfig && echo FILTER_RPC_ARGS= >>/etc/sysconfig/qemu-ga && "
    "systemctl enable qemu-guest-agent; systemctl restart qemu-guest-agent"
)


def provision_script(distro, desktop=True):
    """The first-boot commands for a catalog VM, run by cloud-init."""
    steps = [
        PERMISSIVE,
        distro.agent,
        AGENT_ON,
        distro.tools,
    ]
    if desktop:
        steps += [
            distro.desktop,
            AUTOLOGIN,
            # --force: take display-manager.service over from any display manager the image already had
            "systemctl enable --force lightdm || systemctl enable display-manager",
            "systemctl set-default graphical.target",
        ]
    # every step logs to one file and a failed one is noted, so the rest still runs; the marker means done
    body = "\n".join(
        f"( {s} ) >>/var/log/yemu-provision.log 2>&1 || echo {shlex.quote('FAILED: ' + s)} >>{DONE_MARKER}.err"
        for s in steps
    )
    return f"#!/bin/sh\n{body}\ntouch {DONE_MARKER}\n"
