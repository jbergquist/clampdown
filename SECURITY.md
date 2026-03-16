<\!-- SPDX-License-Identifier: GPL-3.0-only -->

# Security policy

## Reporting a vulnerability

Report security issues via **GitHub Security Advisories** on this repository — not as public issues. This keeps details private until a fix is ready.

Navigate to the **Security** tab → **Advisories** → **New draft security advisory**.

Include:
- Description of the issue
- Steps to reproduce
- Affected components (launcher, sidecar, sandbox-seal, OCI hooks, network policy)
- Whether you have a suggested fix

## Threat model

Clampdown runs an AI coding agent inside a hardened container sandbox. The sandbox is designed to isolate the agent from:

- **Host filesystem** — Landlock filesystem MAC + read-only rootfs + protected `.git` and config paths
- **Network exfiltration** — iptables default-deny allowlist scoped to required API domains
- **Privilege escalation** — `cap-drop=ALL`, `no-new-privileges`, seccomp (~132 blocked syscalls)
- **Host modification** — sidecar UID mapping + host-side inotify tripwire (snapshot + restore)
- **Nested container breakout** — OCI hooks enforce 17 security checks on every `podman run`
- **Kernel exploit primitives** — seccomp blocks io_uring, eBPF, MSG_OOB, MAP_GROWSDOWN, POSIX MQ, TTY line discipline change, splice/vmsplice, CLONE_NEWUSER

For a complete description of all defense layers, see [`DIAGRAM.md`](DIAGRAM.md).

## Known limitations

These are accepted design constraints, not bugs. They are disclosed here so users can make informed trust decisions.

**Build containers skip Landlock.**
`podman build` uses buildah internally, which does not invoke the `precreate` OCI hook. Build containers receive seccomp enforcement, the `createRuntime` security-policy checks (17 checks), and sensitive path masking via containers.conf volumes, but not Landlock filesystem MAC or UID enforcement via seal-inject. This is a limitation of the OCI hook specification — `precreate` is a podman extension not implemented in buildah.

**Egress filtering is IP-based, not domain-based.**
The agent firewall resolves the domain allowlist to IP addresses at session startup and installs iptables rules for those IPs. A sufficiently motivated agent could exfiltrate data via DNS queries (rate-limited to 10/s) or by using allowlisted IP addresses after connecting through them. A DNS-intercepting proxy would close this gap but is not currently implemented.

**No kernel isolation boundary.**
Clampdown uses containers, not virtual machines. The agent shares the host
kernel. A kernel exploit executed by the agent could break out of all
container-level protections. This section documents exactly what clampdown
can and cannot prevent.

*What clampdown mitigates.*

The seccomp profiles eliminate the exploit
primitive required by the majority of **known** kernel escape CVEs.
That's the point, it cannot prevent unknown CVEs at the moment.

*What clampdown cannot prevent at all.*

Three kernel bug classes use only
syscalls that every container workload requires. No seccomp profile, no
capabilities, no Landlock, no namespaces can block them:

| Bug class | Syscalls | Why unfilterable |
|-----------|----------|-----------------|
| futex UAF | `futex()` | Required for all threading (pthreads, Go, Node.js) |
| AF_UNIX GC race | `socket(AF_UNIX)`, `sendmsg(SCM_RIGHTS)`, `recvmsg(MSG_PEEK)` | Required for all container IPC |
| Dirty COW class | `mmap()`, `madvise()`, `write()` to `/proc/self/mem` | Required for memory management; /proc/self/mem unmaskable |

The host-side inotify tripwire detects post-exploitation host file
modifications and restores from sha256-verified snapshots. It cannot
prevent the exploit — it detects and contains the damage after the fact.

### VM based isolation is planned for the future

This will be basically a VM that runs the whole stack inside.
Advisable for profiles where isolation from host is paramaount.

## Kernel requirements

| Requirement | Minimum kernel | Behavior if absent |
|-------------|---------------|---------------------|
| Landlock V3 (filesystem + Truncate) | 6.2 | Hard fail — session refuses to start |
| Landlock V4 (TCP connect) | 6.7 | BestEffort — TCP port restriction unavailable |
| Landlock V5 (IoctlDev) | 6.10 | BestEffort — device ioctl control unavailable |
| Landlock V6 (IPC scoping) | 6.12 | Warning — abstract unix socket + signal isolation degraded |
| Landlock V7 (audit logging) | 6.15 | BestEffort — denied access logging unavailable |
| cgroup v2 | 5.2 | Required for `pids_limit` enforcement |
