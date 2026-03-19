// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// open_tree flags (not exported by x/sys/unix).
const (
	openTreeClone = 1
	atRecursive   = 0x8000
)

// logf writes a timestamped audit line to stderr.
func logf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "clampdown: %s seccomp-notif: %s\n",
		time.Now().UTC().Format(time.RFC3339), msg)
}

// readStringFromPID reads a NUL-terminated string from another process's
// memory via /proc/<pid>/mem at the given address.
func readStringFromPID(pid uint32, addr uint64) (string, error) {
	if addr == 0 {
		return "", nil
	}
	path := fmt.Sprintf("/proc/%d/mem", pid)
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	buf := make([]byte, 4096)
	n, err := f.ReadAt(buf, int64(addr))
	if n == 0 {
		return "", fmt.Errorf("read %s at 0x%x: %w", path, addr, err)
	}

	for i := 0; i < n; i++ {
		if buf[i] == 0 {
			return string(buf[:i]), nil
		}
	}
	return string(buf[:n]), nil
}

// exePath returns the executable path for a process, or "" on error.
func exePath(pid uint32) string {
	result := ""
	result, _ = os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	return result
}

// resolvePath cleans a path and resolves relative paths using the
// process's cwd.
func resolvePath(raw string, pid uint32) string {
	if raw == "" {
		return ""
	}
	if raw[0] != '/' {
		cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
		if err == nil {
			raw = filepath.Join(cwd, raw)
		}
	}
	return filepath.Clean(raw)
}

// readPIDNS returns the PID namespace identifier for a process
// (e.g., "pid:[4026531836]"). Used to distinguish sidecar processes
// from nested container processes.
func readPIDNS(pid int) string {
	link, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", pid))
	if err != nil {
		return ""
	}
	return link
}

// isSidecarPIDNS checks whether a process is in the sidecar's PID namespace.
// Compares /proc/<pid>/ns/pid (a symlink like "pid:[4026531836]") against
// PID 1's cached value. A match means the caller sees the sidecar's PID 1
// in its procfs -- mounting proc would expose /proc/1/mem. A mismatch means
// the caller is in a nested container's PID namespace (security-policy
// requires PID isolation), where procfs only shows its own processes.
func isSidecarPIDNS(pid uint32, myPIDNS string) bool {
	if myPIDNS == "" {
		return true // conservative: if we can't read our own NS, block
	}
	ns := readPIDNS(int(pid))
	return ns == "" || ns == myPIDNS
}

// runSupervisor handles seccomp notifications on the notification FD.
// It applies path-based policy for mount operations and PID-based
// policy for ptrace/process_vm_* targeting PID 1.
func runSupervisor(notifFD int, protected map[string]bool, workdir string) {
	myPID := uint64(os.Getpid())
	myPIDNS := readPIDNS(int(myPID))

	for {
		var notif seccompNotif
		var resp seccompNotifResp

		_, _, errno := unix.Syscall(unix.SYS_IOCTL,
			uintptr(notifFD),
			unix.SECCOMP_IOCTL_NOTIF_RECV,
			uintptr(unsafe.Pointer(&notif)))
		if errno != 0 {
			if errno == unix.EBADF || errno == unix.ENODEV {
				return
			}
			if errno == unix.EINTR {
				continue
			}
			logf("RECV error: %v", errno)
			continue
		}

		resp.ID = notif.ID
		pid := notif.PID
		nr := notif.Data.NR

		switch nr {
		case int32(unix.SYS_UMOUNT2):
			handleUmount2(&notif, &resp, pid, protected, notifFD)

		case int32(unix.SYS_MOUNT):
			handleMount(&notif, &resp, pid, protected, workdir, myPIDNS, notifFD)

		case int32(unix.SYS_MOUNT_SETATTR):
			handleMountSetattr(&notif, &resp, pid, protected, notifFD)

		case int32(unix.SYS_MOVE_MOUNT):
			handleMoveMount(&notif, &resp, pid, protected, notifFD)

		case int32(unix.SYS_OPEN_TREE):
			handleOpenTree(&notif, &resp, pid, workdir, notifFD)

		case int32(unix.SYS_FSOPEN):
			handleFsopen(&notif, &resp, pid, myPIDNS, notifFD)

		case int32(unix.SYS_FSCONFIG), int32(unix.SYS_FSMOUNT):
			// Dangerous paths blocked at fsopen (procfs) and move_mount (target).
			resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE

		case int32(unix.SYS_PTRACE), int32(unix.SYS_PROCESS_VM_READV), int32(unix.SYS_PROCESS_VM_WRITEV):
			handlePIDCheck(&notif, &resp, pid, myPID, nr, notifFD)

		default:
			resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
		}

		sendResp(notifFD, &resp)
	}
}

// handleUmount2 blocks umount2 on protected paths.
// umount2(target, flags): arg0 = target path pointer.
func handleUmount2(notif *seccompNotif, resp *seccompNotifResp, pid uint32, protected map[string]bool, notifFD int) {
	target, err := readStringFromPID(pid, notif.Data.Args[0])
	if err != nil {
		logf("WARNING: umount2 cannot read path pid=%d: %v (allowing)", pid, err)
		resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
		return
	}
	target = resolvePath(target, pid)

	if !checkNotifValid(notifFD, &notif.ID) {
		return
	}

	if isProtected(target, protected) {
		resp.Error = -int32(unix.EPERM)
		logf("BLOCKED umount2 path=%s pid=%d bin=%s", target, pid, exePath(pid))
	} else {
		resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
	}
}

// handleMount applies policy to all mount() calls.
// mount(source, target, fstype, flags, data):
//
//	arg0 = source, arg1 = target, arg2 = fstype, arg3 = flags.
//
// Policy:
//   - Target is a protected/masked path -> BLOCK (prevents overlay/remount)
//   - MS_BIND without MS_REC and source contains the workdir -> BLOCK
//     (prevents non-recursive bind that strips /dev/null sub-mounts)
//   - Procfs mount from sidecar PID namespace -> BLOCK
//     (prevents mounting new procfs to access /proc/1/mem)
//   - Otherwise -> ALLOW
func handleMount(notif *seccompNotif, resp *seccompNotifResp, pid uint32, protected map[string]bool, workdir, myPIDNS string, notifFD int) {
	target, err := readStringFromPID(pid, notif.Data.Args[1])
	if err != nil {
		logf("WARNING: mount cannot read target pid=%d: %v (allowing)", pid, err)
		resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
		return
	}
	target = resolvePath(target, pid)

	flags := notif.Data.Args[3]

	// For bind mounts, also read the source.
	var source string
	if flags&unix.MS_BIND != 0 {
		source, err = readStringFromPID(pid, notif.Data.Args[0])
		if err != nil {
			source = ""
		} else {
			source = resolvePath(source, pid)
		}
	}

	// Read filesystem type for procfs check (arg2, may be NULL for bind/remount).
	var fstype string
	if notif.Data.Args[2] != 0 {
		fstype, _ = readStringFromPID(pid, notif.Data.Args[2])
	}

	if !checkNotifValid(notifFD, &notif.ID) {
		return
	}

	// Block any mount targeting a protected path (overlay, remount, tmpfs, bind over it).
	if isProtected(target, protected) {
		resp.Error = -int32(unix.EPERM)
		logf("BLOCKED mount target=%s pid=%d flags=0x%x bin=%s", target, pid, flags, exePath(pid))
		return
	}

	// Block non-recursive bind mount where the source is the workdir or
	// an ancestor of it. A non-recursive bind of any path that contains
	// the workdir doesn't carry the /dev/null sub-mounts, exposing masked files.
	if workdir != "" && flags&unix.MS_BIND != 0 && flags&unix.MS_REC == 0 && source != "" {
		if source == workdir || isSubPath(source, workdir) {
			resp.Error = -int32(unix.EPERM)
			logf("BLOCKED mount(MS_BIND) source=%s target=%s pid=%d bin=%s (workdir ancestor bind)", source, target, pid, exePath(pid))
			return
		}
	}

	// Block procfs mounts from the sidecar's PID namespace. A new procfs
	// mount exposes /proc/1/mem without the /dev/null mask. Nested
	// container processes (different PID namespace) are allowed -- their
	// procfs only shows their own PID namespace, not the sidecar's PID 1.
	if fstype == "proc" && isSidecarPIDNS(pid, myPIDNS) {
		resp.Error = -int32(unix.EPERM)
		logf("BLOCKED mount(proc) target=%s pid=%d bin=%s (sidecar PID namespace)", target, pid, exePath(pid))
		return
	}

	resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
}

// handleMountSetattr blocks mount_setattr on protected paths.
// mount_setattr(dirfd, path, flags, attr, size): arg1 = path pointer.
func handleMountSetattr(notif *seccompNotif, resp *seccompNotifResp, pid uint32, protected map[string]bool, notifFD int) {
	path, err := readStringFromPID(pid, notif.Data.Args[1])
	if err != nil {
		logf("WARNING: mount_setattr cannot read path pid=%d: %v (allowing)", pid, err)
		resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
		return
	}
	path = resolvePath(path, pid)

	if !checkNotifValid(notifFD, &notif.ID) {
		return
	}

	if isProtected(path, protected) {
		resp.Error = -int32(unix.EPERM)
		logf("BLOCKED mount_setattr path=%s pid=%d bin=%s", path, pid, exePath(pid))
	} else {
		resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
	}
}

// handleMoveMount blocks move_mount targeting protected paths.
// move_mount(from_dirfd, from_path, to_dirfd, to_path, flags):
//
//	arg1 = from_path, arg3 = to_path.
func handleMoveMount(notif *seccompNotif, resp *seccompNotifResp, pid uint32, protected map[string]bool, notifFD int) {
	toPath, err := readStringFromPID(pid, notif.Data.Args[3])
	if err != nil {
		logf("WARNING: move_mount cannot read to_path pid=%d: %v (allowing)", pid, err)
		resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
		return
	}
	toPath = resolvePath(toPath, pid)

	if !checkNotifValid(notifFD, &notif.ID) {
		return
	}

	if isProtected(toPath, protected) {
		resp.Error = -int32(unix.EPERM)
		logf("BLOCKED move_mount to_path=%s pid=%d bin=%s", toPath, pid, exePath(pid))
	} else {
		resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
	}
}

// handleOpenTree blocks non-recursive open_tree clones of the workdir
// or any ancestor. open_tree(dirfd, path, flags): arg1 = path, arg2 = flags.
// A non-recursive OPEN_TREE_CLONE strips sub-mounts (like non-recursive bind),
// exposing masked file contents at the detached mount.
func handleOpenTree(notif *seccompNotif, resp *seccompNotifResp, pid uint32, workdir string, notifFD int) {
	flags := notif.Data.Args[2]

	// Only care about OPEN_TREE_CLONE without AT_RECURSIVE.
	if flags&openTreeClone == 0 || flags&atRecursive != 0 {
		resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
		return
	}

	path, err := readStringFromPID(pid, notif.Data.Args[1])
	if err != nil {
		logf("WARNING: open_tree cannot read path pid=%d: %v (allowing)", pid, err)
		resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
		return
	}
	path = resolvePath(path, pid)

	if !checkNotifValid(notifFD, &notif.ID) {
		return
	}

	// Block if path is the workdir or an ancestor of it.
	if workdir != "" && (path == workdir || isSubPath(path, workdir)) {
		resp.Error = -int32(unix.EPERM)
		logf("BLOCKED open_tree(CLONE) path=%s pid=%d bin=%s (workdir ancestor clone)", path, pid, exePath(pid))
		return
	}

	resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
}

// handleFsopen blocks fsopen("proc") from the sidecar's PID namespace.
// fsopen(fsname, flags): arg0 = fsname string.
// A new procfs filesystem context from the sidecar's PID namespace would
// expose /proc/1/mem without the /dev/null mask.
func handleFsopen(notif *seccompNotif, resp *seccompNotifResp, pid uint32, myPIDNS string, notifFD int) {
	fsname, err := readStringFromPID(pid, notif.Data.Args[0])
	if err != nil {
		logf("WARNING: fsopen cannot read fsname pid=%d: %v (allowing)", pid, err)
		resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
		return
	}

	if !checkNotifValid(notifFD, &notif.ID) {
		return
	}

	if fsname == "proc" && isSidecarPIDNS(pid, myPIDNS) {
		resp.Error = -int32(unix.EPERM)
		logf("BLOCKED fsopen(proc) pid=%d bin=%s (sidecar PID namespace)", pid, exePath(pid))
		return
	}

	resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
}

// handlePIDCheck blocks ptrace/process_vm_readv/process_vm_writev
// targeting PID 1 (the supervisor process).
//
//	ptrace(op, pid, ...):     arg1 = target pid
//	process_vm_readv(pid, ...):  arg0 = target pid
//	process_vm_writev(pid, ...): arg0 = target pid
func handlePIDCheck(notif *seccompNotif, resp *seccompNotifResp, callerPID uint32, myPID uint64, nr int32, notifFD int) {
	targetPID := notif.Data.Args[0]
	if nr == int32(unix.SYS_PTRACE) {
		targetPID = notif.Data.Args[1]
	}

	if !checkNotifValid(notifFD, &notif.ID) {
		return
	}

	if targetPID == myPID {
		resp.Error = -int32(unix.EPERM)
		name := "ptrace"
		if nr == int32(unix.SYS_PROCESS_VM_READV) {
			name = "process_vm_readv"
		} else if nr == int32(unix.SYS_PROCESS_VM_WRITEV) {
			name = "process_vm_writev"
		}
		logf("BLOCKED %s targeting PID 1 from pid=%d bin=%s", name, callerPID, exePath(callerPID))
	} else {
		resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
	}
}
