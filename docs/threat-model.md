# YEMU threat model

YEMU runs untrusted code on purpose. This document covers:

- what YEMU protects
- who and what it defends against
- where the trust boundaries are
- which mitigations exist
- which risks remain for the analyst to manage

## What YEMU protects

| Asset | Why it matters |
|---|---|
| **The host** (the analyst's workstation) | A guest escape or a host-side parser bug would give the sample the analyst's machine. |
| **The analyst's network and the internet** | A detonated sample must not spread, attack other hosts, or reach its operators. Reaching them would reveal the analysis and could trigger real-world harm. |
| **Integrity of results** | A sample should not be able to forge or hide its own behaviour in the report, or poison later analyses. |
| **Secrets on the host** | Credentials, SSH keys and other data must never be copied into a guest. |

## Adversaries

1. **The sample.** It runs as root inside the guest. Assume it is hostile, VM-aware, and actively trying to escape or tamper.
2. **Content the sample controls** that flows back to the host: strace logs, file names, YARA output, `/proc` data and the network capture.
3. **Rule sources.** A compromised or malicious YARA repository could ship crafted archives or rules.
4. **Local configuration mistakes**, for example a VM attached to a NAT or bridged network.

Out of scope: a malicious local user with access to the host account, and supply-chain compromise of QEMU, libvirt, Python or PyPI dependencies. Keep those updated.

## Trust boundaries and data flows

```
 host (trusted)                                 guest (hostile)
 ─────────────────────────────────────────────  ─────────────────────────────
 YEMU  ──QMP (127.0.0.1)──────────────────────► QEMU process
       ──QGA over virtio-serial───────────────► qemu-guest-agent (root in guest)
             · guest-file-write: sample, rules  ─►
             · guest-exec: fixed, quoted cmds   ─►
             ◄─ command output (strace logs, YARA output, /proc data)
             ◄─ guest-file-read: capture.pcap
 scapy / YARA parser / report writers  ◄── parse everything above
```

## Mitigations in place

| Risk | Mitigation |
|---|---|
| Sample reaches the network | The analysis network is isolated by default: libvirt network with no `<forward>`, or QEMU user-mode with `restrict=on`. NAT is used only while provisioning, before any sample exists. Every run checks the VM's interfaces and logs `CRITICAL` if any is internet- or LAN-facing. |
| Leftovers from an earlier sample | The VM is reverted to `clean-baseline` before every run. **If the revert fails, the analysis aborts before the sample executes.** |
| Runaway analysis | Hard `[analysis].timeout`. The VM is always powered off in a `finally` block. There are also caps on sample size, stored events and PCAP size. |
| Command injection through guest data | Guest paths are random per run and `shlex`-quoted. Guest file listings are only accepted if they match `strace.<pid>`. Memory-scan PIDs must be numeric. No guest-supplied string is ever interpolated into a host command. |
| Host disk filled by the guest | The PCAP size is checked before it is pulled back. Events are capped, and guest command output is bounded by the agent's timeouts. |
| Malicious rule archive | GitHub URLs only. The commit is pinned or resolved and recorded. Downloads and individual files are size-capped. Zip-slip paths are rejected. Every rule must compile. The new set is staged and swapped in atomically. |
| Guest credentials | Each VM gets a random console password, and SSH password login is off. YEMU only talks to the guest through the agent. |
| Forged report content | Reports escape guest strings (the PDF uses ReportLab's `escape`). The GUI renders guest data as plain text, never HTML. Scoring only counts behaviour attributed to the sample's own process tree. |

## Residual risks (what the analyst must manage)

- **Hypervisor escapes.** QEMU, KVM, WHPX, virtio devices, the slirp user-mode network stack and qemu-guest-agent all have had CVEs. Keep QEMU and the host OS patched. For hostile samples, use a **dedicated analysis machine** that holds no sensitive data.
- **Host-side parsers.** scapy (PCAP), YARA and ReportLab parse attacker-influenced data on the host. A parser bug could be exploitable. Running YEMU as an unprivileged user limits the damage. Never run it as root or Administrator.
- **Evasion.** Samples can detect VMs, strace, or the lack of a network, and then behave benignly. A `clean` verdict means "nothing observed", not "safe".
- **Guest agent trust.** Output from the guest (strace logs, YARA hits in memory) is produced inside a compromised machine and can be forged by a root-level sample. Treat it as evidence, not proof.
- **Mistakes in `allow_internet`.** Setting `[network].allow_internet = true` or using NAT or bridged networks deliberately exposes live infrastructure to the sample.
- **Shared resources.** Don't add shared folders, clipboard sharing, USB passthrough or port forwards to analysis VMs. YEMU doesn't configure any, but manual changes in virt-manager could add them.

## Responsible use

YEMU is for analysing malware you are authorised to handle: your own incident response, research samples, or CTF material. Don't use it to develop, test or tune malware against detection. Follow your organisation's handling policy and the laws that apply to you. Keep samples in password-protected archives outside the analysis environment.
