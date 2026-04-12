<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Seccomp-Notif Supervisor

The sidecar entrypoint runs a seccomp-notif supervisor that intercepts 20 syscalls
and applies policy-based decisions at runtime. This document covers the supervisor
architecture, intercepted syscalls, decision flows, and data structures.

For background on seccomp-notify API and ecosystem support, see [SECCOMP.md](SECCOMP.md).

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│ SIDECAR ENTRYPOINT (PID 1)                                              │
│                                                                         │
│  main()                                                                 │
│    │                                                                    │
│    ├─► Harden /proc/sys (bind-mount read-only)                          │
│    ├─► Bootstrap cgroup v2 (nsdelegate, controllers)                    │
│    ├─► Bootstrap iptables firewall (agent + pod chains)                 │
│    ├─► Write /run/sandbox/{uid,gid}, bind-mount RO                      │
│    ├─► Discover protected paths (mount points)                          │
│    ├─► buildExecAllowlist() ── walk rootfs, SHA-256 hash executables    │
│    ├─► hardenPID1() ── bind /dev/null over /proc/1/mem                  │
│    ├─► runtime.LockOSThread()                                           │
│    ├─► buildNotifFilter() ── create BPF program                         │
│    ├─► installFilter() ── install seccomp-notif, get listener fd        │
│    ├─► go runSupervisor() ── start event loop goroutine                 │
│    └─► exec workload (podman system service)                            │
│                                                                         │
│  runSupervisor()                                                        │
│    │                                                                    │
│    └─► for { recv notification → dispatch to handler → send response }  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

**Two-layer security model:**

1. **Workload seccomp profile** (external, applied by container runtime)
   - Blocks dangerous syscalls entirely (`SCMP_ACT_ERRNO` / `SCMP_ACT_KILL`)
   - Applied to agent and nested containers
   - ~150 syscalls blocked

2. **Seccomp-notif filter** (internal, in sidecar)
   - Intercepts whitelisted syscalls via `SECCOMP_RET_USER_NOTIF`
   - Supervisor evaluates policy: path checks, exec hash verification, PID validation
   - Returns `CONTINUE` (allow kernel to execute) or `EPERM`/`EACCES` (block)

The workload profile already blocks `mount`/`umount` for nested containers. The
supervisor primarily handles sidecar-level processes that legitimately need these
syscalls (podman, crun, netavark).

---

## Intercepted Syscalls (20 total)

### Mount Operations (5)

| Syscall | Handler | Policy |
|---------|---------|--------|
| `mount` | `handleMount` | Validate target not protected; bind sources in allowlist; fstype in allowlist |
| `umount2` | `handleProtectedPathOp` | Block if target is protected mount point |
| `mount_setattr` | `handleProtectedPathOp` | Block if target is protected |
| `move_mount` | `handleProtectedPathOp` | Block if target is protected |
| `open_tree` | `handleOpenTree` | Block non-recursive CLONE of workdir (strips sub-mounts) |

### New Mount API (3) - Blocked from sidecar PID namespace

| Syscall | Handler | Policy |
|---------|---------|--------|
| `fsopen` | `handleSidecarPIDNSBlock` | Block from sidecar PID NS; allow nested containers |
| `fsconfig` | `handleSidecarPIDNSBlock` | Block from sidecar PID NS; allow nested containers |
| `fsmount` | `handleSidecarPIDNSBlock` | Block from sidecar PID NS; allow nested containers |

### Process/Memory Access (3) - Protecting PID 1

| Syscall | Handler | Policy |
|---------|---------|--------|
| `ptrace` | `handlePIDCheck` | Block if target PID == 1 |
| `process_vm_readv` | `handlePIDCheck` | Block if target PID == 1 |
| `process_vm_writev` | `handlePIDCheck` | Block if target PID == 1 |

### Execution (2) - Hash-verified allowlist

| Syscall | Handler | Policy |
|---------|---------|--------|
| `execve` | `handleExecve` | Sidecar PID NS: verify SHA-256 in allowlist; nested: allow |
| `execveat` | `handleExecveat` | Same as execve, handles AT_EMPTY_PATH/AT_FDCWD |

### File Operations (5) - Protecting read-only/masked paths

| Syscall | Handler | Policy |
|---------|---------|--------|
| `openat` | `handleOpenat` | Sidecar PID NS: block /proc/1/* sensitive paths; nested: allow |
| `unlinkat` | `handleProtectedPathOp` | Block if path is protected |
| `symlinkat` | `handleProtectedPathOp` | Block if path is protected |
| `linkat` | `handleLinkat` | Block if source or dest is protected |
| `renameat2` | `handleRenameat2` | Block if source or dest is protected |

### Firewall (2) - Blocking unauthorized netfilter modifications

| Syscall | Handler | Policy |
|---------|---------|--------|
| `setsockopt` | `handleSetsockopt` | Block IPT_SO_SET_REPLACE except xtables-nft-multi→netavark |
| `socket` | `handleSocket` | Block NETLINK_NETFILTER except xtables-nft-multi→netavark |

---

## Decision Flowchart

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         SUPERVISOR EVENT LOOP                           │
│                                                                         │
│   SECCOMP_IOCTL_NOTIF_RECV ──► notification (syscall nr, pid, args)     │
│                                       │                                 │
│                              ┌────────▼────────┐                        │
│                              │ Dispatch by nr  │                        │
│                              └────────┬────────┘                        │
│          ┌──────────┬──────────┬───────┼───────┬──────────┬─────────┐   │
│          ▼          ▼          ▼       ▼       ▼          ▼         ▼   │
│      MOUNT      UNMOUNT     EXEC    PID1    OPENAT   FIREWALL   LINK/   │
│      FAMILY     FAMILY     FAMILY  PROTECT  (sidecar) FAMILY   RENAME   │
│          │          │          │       │       │          │         │   │
│          ▼          ▼          ▼       ▼       ▼          ▼         ▼   │
│   ┌──────────┐ ┌────────┐ ┌───────┐ ┌─────┐ ┌──────┐ ┌────────┐ ┌─────┐ │
│   │ Read     │ │ Read   │ │ Check │ │Check│ │ Read │ │ Check  │ │Read │ │
│   │ target   │ │ path   │ │ PID   │ │PID  │ │ path │ │ caller │ │both │ │
│   │ path     │ │        │ │ NS    │ │arg  │ │      │ │ chain  │ │paths│ │
│   └────┬─────┘ └───┬────┘ └───┬───┘ └──┬──┘ └──┬───┘ └───┬────┘ └──┬──┘ │
│        ▼           ▼          │        │       │         │         │    │
│   ┌──────────┐ ┌─────────┐    │        │       │         │         │    │
│   │ Protected│ │Protected│    │        │       │         │         │    │
│   │ path?    │ │ path?   │    │        │       │         │         │    │
│   └─┬────┬───┘ └─┬────┬──┘    │        │       │         │         │    │
│    YES   NO     YES  NO       │        │       │         │         │    │
│     │     │      │    │       │        │       │         │         │    │
│     ▼     ▼      ▼    ▼       ▼        ▼       ▼         ▼         ▼    │
│    BLOCK  ...   BLOCK ALLOW   ...      ...    ...       ...       ...   │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                        RESPONSE                                  │   │
│  │  CONTINUE (val=0, flags=CONTINUE) ── allow kernel to execute     │   │
│  │  ERROR (val=-1, error=EPERM/EACCES) ── block syscall             │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                       │                                 │
│                  SECCOMP_IOCTL_NOTIF_SEND ◄───────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Key Data Structures

### Exec Allowlist

Built at startup by walking the rootfs and SHA-256 hashing every executable.

```go
type execAllowlist struct {
    entries map[string]execEntry  // path → entry
}

type execEntry struct {
    hash  [32]byte   // SHA-256 of file contents
    dev   uint64     // device ID
    ino   uint64     // inode number
    size  int64      // file size
    mtime int64      // modification time (nanoseconds)
}
```

**Verification flow:**
1. Fast path: `stat()` file, if (dev, ino, size, mtime) match → approved
2. Slow path: on metadata mismatch, re-hash and compare against stored hash
3. Only includes files from rootfs device (skips bind mounts)

### Allowed Bind Mount Sources

Path prefix allowlist for bind mounts in sidecar PID namespace:

| Category | Paths |
|----------|-------|
| Infrastructure | `/proc/self`, `/proc/thread-self`, `/run/user/0`, `/run/netns`, `/dev/char`, `/dev/pts` |
| Container storage | `/run/containers`, `/var/cache/containers`, `/var/lib/containers/storage`, `/var/run/containers/storage` |
| Buildah staging | `/var/tmp` |
| Credential forwarding | `/run/credentials` |
| Device files | `/dev/full`, `/dev/null`, `/dev/random`, `/dev/tty`, `/dev/urandom`, `/dev/zero` |
| Sandbox files | `/empty`, `/rename_exdev_shim.so`, `/sandbox-seal` |

Plus: workdir path (dynamically added).

### Protected Paths

Discovered at startup from mount points. Includes:
- Bind-mounted masked paths (e.g., /dev/null over sensitive files)
- Read-only bind mounts over protected config files

Operations blocked on protected paths:
- `umount2`, `mount_setattr`, `move_mount`
- `unlinkat`, `symlinkat`, `linkat`, `renameat2`
- `mount` (as target)

### Protected /proc/1 Paths (11)

Defense-in-depth against PID 1 information leaks (even though /proc/1/mem is masked):

```
/proc/1/auxv    /proc/1/cwd      /proc/1/environ  /proc/1/exe
/proc/1/io      /proc/1/maps     /proc/1/mem      /proc/1/pagemap
/proc/1/root    /proc/1/stack    /proc/1/syscall
```

### Allowed Filesystem Types (sidecar PID NS only)

```
cgroup2  devpts  mqueue  none  overlay  sysfs  tmpfs
```

Used during container setup by crun (OCI runtime).

---

## PID Namespace Isolation

The supervisor uses PID namespace membership to distinguish security contexts:

```go
func inSidecarPIDNS(pid int) bool {
    // Read /proc/<pid>/ns/pid symlink (format: "pid:[xxxxxx]")
    // Compare against PID 1's namespace
    // Match = sidecar PID NS; Mismatch = nested container PID NS
}
```

**Enforcement matrix:**

| Syscall | Sidecar PID NS | Nested Container PID NS |
|---------|----------------|-------------------------|
| mount | Full validation | Full validation |
| fsopen/fsconfig/fsmount | **BLOCKED** | ALLOWED |
| execve/execveat | Hash-verified allowlist | ALLOWED |
| openat (/proc/1/*) | **BLOCKED** | ALLOWED |
| setsockopt (netfilter) | Strict path validation | ALLOWED |
| socket (NETLINK_NETFILTER) | Strict path validation | ALLOWED |
| ptrace/process_vm_* | Check if targeting PID 1 | Check if targeting PID 1 |

**Rationale:**
- Sidecar processes can manipulate host namespaces → tight restrictions
- Nested containers run in isolated namespace → restrictions relax
- They can't see or affect host PID 1 from their namespace

---

## TOCTOU Mitigations

Time-of-check vs time-of-use is a fundamental limitation of seccomp-notify
(see [SECCOMP.md](SECCOMP.md) for details). The supervisor applies these mitigations:

1. **Notification validity check** (`checkNotifValid()`)
   - Called after reading from child memory, before decision
   - Tightens the window between read and response

2. **Integer-only arguments for netfilter**
   - Firewall checks use only integer args (level, optname)
   - No pointer dereferences = no additional TOCTOU

3. **Read-only allowlist**
   - Exec allowlist built once at startup on read-only rootfs
   - No TOCTOU on allowlist modifications

4. **Path resolution in target namespace**
   - Uses `/proc/<pid>/root` to resolve paths through target's mount namespace
   - Catches symlink traversal attacks

---

## BPF Filter Structure

The filter program (from `buildNotifFilter`) uses a simple comparison chain:

```
[0] Load architecture from seccomp_data
[1] JEQ → architecture check
[2] KILL_PROCESS on arch mismatch
[3] Load syscall number
[4..4+n-1] For each of 20 syscalls: JEQ → jump to USER_NOTIF
[4+n] Default: ALLOW (falls through)
[4+n+1] USER_NOTIF (supervisor catches)
```

Installation attempts three flag combinations:
1. `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` (5.19+) — preferred
2. `TSYNC | NEW_LISTENER` — fallback
3. `NEW_LISTENER` only — last resort

---

## Handler Details

### handleMount

```
1. Read target path from /proc/<pid>/mem
2. Resolve target (relative → absolute, symlink resolution)
3. If target is protected mount point → BLOCK (EPERM)
4. If MS_BIND flag set:
   a. Read source path
   b. Validate source against allowedBindSources
   c. If non-recursive bind (no MS_REC) and source contains workdir → BLOCK
      (prevents stripping /dev/null sub-mounts)
5. If non-bind, non-remount mount with disallowed fstype → BLOCK (EPERM)
6. Otherwise → ALLOW (CONTINUE)
```

### handleExecve / handleExecveat

```
1. Check if caller is in sidecar PID namespace
2. If nested container → ALLOW (no restriction)
3. Resolve executable path:
   - execve: relative to process cwd
   - execveat: handles AT_EMPTY_PATH, AT_FDCWD, or dirfd-relative
4. Look up resolved path in exec allowlist
5. Fast path: stat matches → ALLOW
6. Slow path: re-hash, compare → ALLOW or BLOCK (EACCES)
```

### handleSetsockopt / handleSocket

```
1. Check if caller is in sidecar PID namespace
2. If nested container → ALLOW
3. Check if netfilter-related (IPT_SO_SET_REPLACE or NETLINK_NETFILTER)
4. If not netfilter → ALLOW
5. Validate caller is /usr/sbin/xtables-nft-multi
6. Validate parent is /usr/local/lib/podman/netavark
7. If valid chain → ALLOW
8. Otherwise → BLOCK (EPERM)
```

---

## Files

| File | Purpose |
|------|---------|
| `entrypoint.go` | main(), startup sequence, exec workload |
| `supervisor.go` | runSupervisor(), notification dispatch loop |
| `handlers.go` | Individual syscall handlers |
| `filter.go` | BPF filter construction and installation |
| `execallow.go` | Exec allowlist building and verification |
| `bootstrap.go` | cgroup and firewall initialization |
| `protect.go` | Protected path discovery, PID 1 hardening |
