# Security policy

## Reporting a vulnerability

Please report security issues privately. Use GitHub's **Report a vulnerability** button on the repository's *Security* tab, or email **armaanguha@gmail.com**. Don't open a public issue.

Include:

- the YEMU version (`yemu --version`)
- your host OS
- the VM backend (`yemu doctor`)
- clear reproduction steps

For guest-to-host issues, describe the class of problem. Don't attach live malware.

You should get an acknowledgement within a few days. Fixes are released as patch versions and credited in the changelog unless you'd rather stay anonymous.

## Supported versions

Only the latest release gets security fixes.

## Scope

In scope: anything that lets a sample running in an analysis VM affect the host, reach the network despite isolation, or tamper with other analyses. The same goes for the rule-sync or report paths.

For what YEMU does and doesn't defend against, see [docs/threat-model.md](docs/threat-model.md). Hypervisor vulnerabilities (QEMU, KVM, WHPX, libvirt) should be reported to those projects.
