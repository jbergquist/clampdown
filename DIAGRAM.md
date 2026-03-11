<!-- SPDX-License-Identifier: GPL-3.0-only -->

# clampdown Security Model

## Container Topology

```
┌──────────────────────────────────────────────────────────────────────────┐
│ HOST                                                                     │
│                                                                          │
│  ┌───────────────┐                                                       │
│  │  Launcher     │  clampdown CLI (Go binary)                            │
│  │  (host PID)   │  Checks Landlock LSM, resolves DNS allowlists,        │
│  │               │  writes seccomp, starts sidecar, proxy, agent.        │
│  └──────┬────────┘                                                       │
│         │                                                                │
│         │  podman run (rootless)                                         │
│         │                                                                │
│  ┌──────▼───────────────────────────────────────────────────────────┐    │
│  │ SIDECAR CONTAINER  (FROM scratch, read-only rootfs)              │    │
│  │                                                                  │    │
│  │  PID 1: /entrypoint                                              │    │
│  │    1. Harden /proc/sys (bind-mount read-only)                    │    │
│  │    2. Bootstrap cgroup v2 (nsdelegate, controllers)              │    │
│  │    3. Build iptables firewall (agent + pod chains)               │    │
│  │    4. Write /run/sandbox/{uid,gid}, chattr +i, bind-mount RO     │    │
│  │    5. exec → podman system service tcp:127.0.0.1:2375            │    │
│  │                                                                  │    │
│  │  Seccomp: seccomp_sidecar.json (denylist, ~80 blocked)           │    │
│  │    Blocks: io_uring, perf_event_open, userfaultfd, modify_ldt,   │    │
│  │    kcmp, process_madvise, kexec_*, init/delete/finit_module,     │    │
│  │    add_key, request_key, splice/tee/vmsplice (Dirty Pipe),       │    │
│  │    open_by_handle_at, swapoff/swapon, acct, vhangup,             │    │
│  │    ioperm/iopl, clock_settime, setdomainname/sethostname,        │    │
│  │    personality (arg-filtered), TIOCSTI/TIOCLINUX/TIOCSETD,       │    │
│  │    SIOCATMARK, IOC_WATCH_QUEUE_SET_FILTER (CVE-2022-0995),       │    │
│  │    MSG_OOB arg-filtered (CVE-2025-38236), mq_* (CVE-2017-11176),│    │
│  │    MAP_GROWSDOWN (CVE-2023-3269), socket family ≥ 17,            │    │
│  │    obsolete syscalls.                                            │    │
│  │    Allows: mount, bpf, clone3, seccomp, keyctl, ptrace           │    │
│  │    — needed by podman/crun for container management.             │    │
│  │                                                                  │    │
│  │  OCI Hooks (intercept nested container lifecycle):               │    │
│  │    precreate:    seal-inject (policy, UID, seal mount)            │    │
│  │    createRuntime: security-policy (17 checks)                    │    │
│  │                                                                  │    │
│  │  ┌─────────────────────────────────────────────────────────┐     │    │
│  │  │ NESTED CONTAINERS  (podman run/build inside sidecar)    │     │    │
│  │  │                                                         │     │    │
│  │  │  Seccomp: workload profile (~125 blocked)               │     │    │
│  │  │  Entrypoint: sandbox-seal -- <original command>         │     │    │
│  │  │  Landlock V7 (derived from mounts by seal-inject)       │     │    │
│  │  │  LD_PRELOAD: rename_exdev_shim.so (EXDEV fallback)      │     │    │
│  │  └─────────────────────────────────────────────────────────┘     │    │
│  └──────────────────────────────────────────────────────────────────┘    │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │ AUTH PROXY CONTAINER  (FROM scratch, read-only rootfs)           │    │
│  │                                                                  │    │
│  │  Entrypoint: sandbox-seal -- auth-proxy                          │    │
│  │  Listens: 127.0.0.1:2376 → upstream API (rewrites auth header)   │    │
│  │                                                                  │    │
│  │  Seccomp: workload profile (~125 blocked)                        │    │
│  │  Landlock: ReadOnly:[/], ReadExec:[/usr/local/bin]               │    │
│  │           ConnectTCP:[443, 53]                                   │    │
│  │  cap-drop=ALL, ulimit core=0:0, 128m, 16 PIDs                    │    │
│  │  No workdir, no HOME, no devices, no shell                       │    │
│  └──────────────────────────────────────────────────────────────────┘    │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │ AGENT CONTAINER  (Alpine, --network container:SIDECAR)           │    │
│  │                                                                  │    │
│  │  Entrypoint: sandbox-seal -- <agent binary>                      │    │
│  │  Seccomp: workload profile (~125 blocked)                        │    │
│  │  Landlock: workdir RWX, rootfs RO, ConnectTCP:[443,2375,2376]    │    │
│  │  cap-drop=ALL, no-new-privileges, read-only rootfs               │    │
│  │                                                                  │    │
│  │  API keys: sk-proxy (dummy), BASE_URL=http://localhost:2376      │    │
│  │  Protected paths: .git/hooks, .envrc, .mcp.json, etc.            │    │
│  │  Inter-container comm: podman networks (not -p port publishing)  │    │
│  └──────────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────────┘
```

## Network Policy

```
                    ┌─────────────────────────┐
                    │      INTERNET           │
                    └────────┬────────────────┘
                             │
              ┌──────────────▼────────────────┐
              │  SIDECAR NETWORK NAMESPACE    │
              │  (shared by proxy + agent)    │
              │                               │
              │  127.0.0.1:2375  podman API   │
              │  127.0.0.1:2376  auth proxy   │
              │                               │
              │  filter/OUTPUT (agent egress) │
              │  ┌────────────────────────┐   │
              │  │ 1. ACCEPT loopback     │   │
              │  │ 2. ACCEPT established  │   │
              │  │ 3. DROP private CIDRs  │   │
              │  │ 4. ACCEPT DNS :53      │   │
              │  │    (10/s burst 20)     │   │
              │  │ 5. ACCEPT allowlist IPs│   │
              │  │ 6. → AGENT_ALLOW       │   │
              │  │ 7. DROP (default deny) │   │
              │  └────────────────────────┘   │
              │                               │
              │  mangle/FORWARD (pod egress)  │
              │  ┌────────────────────────┐   │
              │  │ 1. ACCEPT established  │   │
              │  │ 2. ACCEPT loopback     │   │
              │  │ 3. → POD_ALLOW         │   │
              │  │ 4. DROP private CIDRs  │   │
              │  │ 5. → POD_BLOCK         │   │
              │  │ 6. ACCEPT (default)    │   │
              │  └────────────────────────┘   │
              └───────────────────────────────┘

Blocked CIDRs (IPv4):              Blocked CIDRs (IPv6):
  10.0.0.0/8                         ::1/128
  172.16.0.0/12                      fc00::/7
  192.168.0.0/16                     fe80::/10
  127.0.0.0/8
  169.254.0.0/16 (cloud metadata)
```

## API Key Flow

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────────┐
│   AGENT     │     │  AUTH PROXY  │     │   UPSTREAM API      │
│             │     │              │     │                     │
│ API_KEY=    │     │ Holds real   │     │ api.anthropic.com   │
│ "sk-proxy"  │────▶│ API key      │────▶│                     │
│             │     │              │     │                     │
│ BASE_URL=   │     │ Strips dummy │     │ Receives real       │
│ localhost:  │     │ key, injects │     │ x-api-key header    │
│ 2376        │     │ real key     │     │                     │
└─────────────┘     └──────────────┘     └─────────────────────┘
```

## Capability Model

```
                    Host caps
                        │
           ┌────────────▼────────────┐
           │  SIDECAR (17 caps)      │
           │  SYS_ADMIN  NET_ADMIN   │
           │  SYS_CHROOT SYS_PTRACE  │
           │  SYS_RESOURCE           │
           │  LINUX_IMMUTABLE        │
           │  CHOWN  DAC_OVERRIDE    │
           │  FOWNER FSETID  KILL    │
           │  MKNOD  SETFCAP         │
           │  SETGID SETUID SETPCAP  │
           │  NET_BIND_SERVICE       │
           └────────────┬────────────┘
                        │
           ┌────────────▼────────────┐
           │  PROXY + AGENT (0 caps) │
           │  cap-drop=ALL           │
           └────────────┬────────────┘
                        │
           ┌────────────▼────────────┐
           │  NESTED (10 default)    │
           │  CHOWN DAC_OVERRIDE     │
           │  FOWNER FSETID KILL     │
           │  NET_BIND_SERVICE       │
           │  SETFCAP SETGID SETPCAP │
           │  SETUID                 │
           │                         │
           │  Effective: empty       │
           │  (non-root + no ambient │
           │   + no_new_privileges)  │
           └─────────────────────────┘
```

## OCI Hook Pipeline

```
podman run ...
     │
     ▼
┌──────────────────────────────────────────────┐
│  PRECREATE: seal-inject                      │
│                                              │
│  1. Overwrite process.user → sandbox UID/GID │
│  2. Prepend /.sandbox/seal -- to args        │
│  3. Derive Landlock policy from mounts       │
│  4. Inject SANDBOX_POLICY env var            │
│  5. Add /.sandbox/seal bind mount            │
│  6. Add hidepid=2 to proc mount              │
│  7. Inject opt-in credentials                │
└──────────────────┬───────────────────────────┘
                   │
     container created (crun)
                   │
                   ▼
┌─────────────────────────────────────────────┐
│  CREATERUNTIME: security-policy (17 checks) │
│                                             │
│   1. checkCaps             → EPERM          │
│   2. checkSeccomp          → EPERM          │
│   3. checkNoNewPrivileges  → EPERM          │
│   4. checkNamespaces       → EOPNOTSUPP     │
│   5. checkMounts           → EACCES         │
│   6. checkMountOptions     → EACCES         │
│   7. checkMountPropagation → EPERM          │
│   8. checkRootfsPropagation→ EPERM          │
│   9. checkDevices          → EACCES         │
│  10. checkMaskedPaths      → EPERM          │
│  11. checkReadonlyPaths    → EPERM          │
│  12. checkSysctl           → EPERM          │
│  13. checkRlimits          → EPERM          │
│  14. checkImageRef         → EACCES/warn    │
│  15. checkMountReadonly    → EACCES         │
│  16. checkProcMount        → EPERM          │
│  17. checkAdditionalGids   → EPERM          │
└──────────────────┬──────────────────────────┘
                   │
     container process starts
                   │
                   ▼
┌─────────────────────────────────────────────┐
│  sandbox-seal (PID 1 of nested container)   │
│                                             │
│  1. Parse SANDBOX_POLICY                    │
│  2. applyLandlock (V7 BestEffort)           │
│     → Filesystem (4 tiers + Refer)          │
│     → IoctlDev in write tiers (V5+)         │
│     → IPC scoping (V6+)                     │
│     → ConnectTCP (V4+, if specified)        │
│  3. closeExtraFDs (≥ 3 → close-on-exec)     │
│  4. exec → original entrypoint              │
└─────────────────────────────────────────────┘
```

---

## How It Works

### Startup sequence

The launcher runs on the host as a normal user process. Before starting
any containers, it verifies that Landlock is available in the kernel and
warns if Yama ptrace scope is too permissive or the runtime is rootful.
It resolves the agent's domain allowlist to IP addresses, writes seccomp
profiles to disk, and cleans up stale containers from previous sessions.

The sidecar starts first in detached mode. Its entrypoint hardens
/proc/sys, bootstraps cgroup v2, builds the iptables firewall, writes
the sandbox identity files (UID/GID, made immutable with chattr +i),
then execs the podman system service.

Once the sidecar's podman API responds, the launcher checks whether an
API key is available (from the host environment or .clampdownrc). If a
key is found, the auth proxy starts in detached mode. The launcher waits
for the "proxy: ready" log line, then starts the agent interactively.
If no key is found, the agent starts without a proxy and a warning is
printed.

When the agent exits, all containers are removed in order: agent first,
then proxy, then sidecar.

### API key isolation

The agent never receives real API credentials. The launcher gives it a
dummy key (`sk-proxy`) and overrides the API base URL to point at the
local proxy on port 2376. The proxy receives the agent's request, strips
the dummy auth header, injects the real API key, and forwards the
request to the upstream API. The proxy logs every request (method, path,
duration) to stderr.

Keys are resolved from two sources: the host environment and
.clampdownrc. Neither source is forwarded into the agent container.

For Claude, the SDK reads `ANTHROPIC_BASE_URL` directly. For OpenCode,
most providers do not support a base URL environment variable. The
launcher instead injects `OPENCODE_CONFIG_CONTENT` with the proxy URL,
which OpenCode deep-merges at highest precedence over all other config.
Each agent uses one provider at a time — the first matching key wins.

Even if the agent connects to the upstream API directly on port 443
(allowed by Landlock for infrastructure like models.dev and telemetry),
it sends `sk-proxy` as the key and gets 401. The real key only exists
inside the proxy container, which has no shell, no writable filesystem,
no capabilities, and core dumps disabled.

### Landlock enforcement

sandbox-seal is the Landlock enforcement binary. It runs as the
entrypoint wrapper for the agent, the proxy, and all nested containers.
It reads a JSON policy from `SANDBOX_POLICY`, applies Landlock V7
filesystem rules (four access tiers with IoctlDev for TTY operations),
IPC scoping, and optional TCP port restriction, closes leaked file
descriptors, then execs the real entrypoint.

The agent's policy is built by the launcher from its mount
configuration. The proxy gets a minimal read-only policy with TCP
restricted to ports 443 and 53. Nested container policies are derived
at runtime by the seal-inject OCI hook from each container's mount list.

Landlock requires kernel 6.2+ (ABI V3). Features from V4-V7 degrade
gracefully via BestEffort. Landlock cannot be applied to the sidecar
because mount() internally triggers Landlock path hooks (EPERM).

### Network policy

The sidecar, proxy, and agent share one network namespace. Agent egress
is default-deny with a per-IP allowlist resolved from domain names at
startup. DNS is rate-limited to 10 queries/second. Private CIDRs
(RFC 1918, link-local, cloud metadata) are always blocked.

Nested container (pod) egress is default-allow minus private CIDRs.
Dynamic rules can be added at runtime via `clampdown network`.

### OCI hooks

When the agent runs `podman run` inside the sidecar, two OCI hooks
intercept the container lifecycle before the workload starts.

seal-inject (precreate) overwrites the user to the sandbox UID, prepends
sandbox-seal to the entrypoint, derives a Landlock policy from the mount
list, injects credential mounts if present, and adds hidepid=2 to procfs.
Sensitive /proc and /sys paths are masked via containers.conf volumes
(not seal-inject), which applies to both `podman run` and `podman build`.
seal-inject does not run for build containers.

security-policy (createRuntime) validates the container against 17
checks covering capabilities, seccomp, namespaces, mounts, devices,
masked paths (verifies /dev/null or empty-dir bind mounts), readonly
paths, sysctls, rlimits, image refs, mount propagation, /proc mount
type, and supplementary groups. Each violation blocks the container
with a specific errno.

### Host-side tripwire

The launcher monitors all read-only host paths via inotify. Before the
session starts, it snapshots file content and permissions. Any
modification kills the session immediately. On exit, it restores
modified files and removes unexpected ones.

This is the last defense layer. The sidecar's UID mapping prevents
writes (container uid 0 maps to a sub-UID that doesn't own the files),
but a full escape to the host user would bypass in-container protections.
The tripwire runs outside all namespaces and catches that. Disabled with
`--disable-tripwire`.

---

## Reference

### Seccomp profiles

Two profiles exist. The **sidecar profile** (~80 blocked syscalls) is a
denylist that blocks what the container engine never needs while allowing
mount, bpf, ptrace, and clone for podman. The kernel inherits it to all
child processes.

The **workload profile** (~125 blocked syscalls) is stricter, applied to
the agent, proxy, and nested containers. It blocks container escape
primitives (mount/umount/setns/pivot_root/chroot), the new mount API,
device creation, kernel exploit primitives (io_uring, bpf, userfaultfd,
splice/tee/vmsplice, perf_event_open), user namespace creation
(CLONE_NEWUSER arg-filtered on clone/unshare), privilege escalation
(ptrace, process_vm_*, execveat), kernel keyring, system disruption,
hardware I/O, time manipulation, SysV IPC, POSIX message queues
(CVE-2017-11176 class), terminal injection (TIOCSTI/TIOCLINUX/TIOCSETD),
SIOCATMARK (CVE-2025-38236), MSG_OOB arg-filtered on send*/recv*
(CVE-2025-38236), MAP_GROWSDOWN (CVE-2023-3269 StackRot class), W^X
memory, and socket families >= 17. For nested containers it layers on
top of the sidecar profile.

### Landlock filesystem tiers (nested containers)

| Tier | Rights | Typical paths |
|------|--------|---------------|
| read_exec | read, execute | /bin, /sbin, /usr, /lib, /.sandbox |
| read_only | read | / (entire rootfs) |
| write_noexec | read, write, create, delete, IoctlDev | /dev, /proc, /tmp, /run, /var |
| write_exec | read, write, create, delete, execute, IoctlDev | /home, workdir |

All tiers include Refer (prevents EXDEV). MakeChar/MakeBlock excluded.

### Masked paths (all containers — run + build)

Enforced via containers.conf volumes on the sidecar's read-only rootfs.
Files are masked with /dev/null bind mounts; directories with /.empty
bind mounts. Applies uniformly to both `podman run` and `podman build`.
The agent cannot override these — see VECTORS.md for the full bypass
analysis.

security-policy `checkMaskedPaths` validates defense-in-depth: each path
must be covered by either OCI maskedPaths or a /dev/null/empty-dir bind
mount. The check verifies mount sources are genuinely /dev/null (char
device major 1, minor 3) or empty directories — not attacker-controlled
files.

| Path | Type | Reason |
|------|------|--------|
| /proc/kallsyms | file | Kernel symbol addresses (KASLR bypass) |
| /proc/kcore | file | Physical memory dump |
| /proc/modules | file | Loaded modules (attack surface enumeration) |
| /proc/version | file | Kernel version (exploit selection) |
| /proc/sysrq-trigger | file | System request trigger (DoS) |
| /sys/kernel/vmcoreinfo | file | Crash dump format layout |
| /sys/kernel/debug | dir | ftrace, kprobes |
| /sys/kernel/tracing | dir | ftrace tracing interface |
| /sys/kernel/security | dir | LSM policy files |
| /sys/fs/bpf | dir | Pinned eBPF maps/programs |
| /sys/module | dir | Kernel module parameters |
| /sys/devices/virtual/dmi | dir | Hardware fingerprint |

### File provenance

All Go binaries are static (CGO_ENABLED=0), immune to LD_PRELOAD.
Base images pinned by SHA256 digest.

| Image | File | Notes |
|-------|------|-------|
| Sidecar | /entrypoint | Go, static |
| Sidecar | /sandbox-seal | Go, static (go-landlock, x/sys, psx) |
| Sidecar | /rename_exdev_shim.so | C, musl -nostdlib |
| Sidecar | seal-inject, security-policy | Go, static, stdlib only |
| Sidecar | /usr/local/bin/podman | podman-static v5.8.0 |
| Proxy | /usr/local/bin/auth-proxy | Go, static, stdlib only |
| Proxy | ca-certificates.crt | Alpine CA bundle |
