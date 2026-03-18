// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestBuildNotifFilter(t *testing.T) {
	syscalls := interceptedSyscalls
	filter := buildNotifFilter(auditArch, syscalls)

	// 4 preamble (load arch, check, kill, load NR) + len(syscalls) checks + 2 returns (ALLOW, USER_NOTIF)
	expectedLen := 4 + len(syscalls) + 2
	if len(filter) != expectedLen {
		t.Fatalf("expected %d instructions, got %d", expectedLen, len(filter))
	}

	// Verify arch check is first.
	if filter[0].K != dataOffArch {
		t.Errorf("instruction 0: expected load arch offset %d, got %d", dataOffArch, filter[0].K)
	}

	// Verify arch constant.
	if filter[1].K != auditArch {
		t.Errorf("instruction 1: expected arch %#x, got %#x", auditArch, filter[1].K)
	}

	// Verify KILL_PROCESS on arch mismatch.
	if filter[2].K != unix.SECCOMP_RET_KILL_PROCESS {
		t.Errorf("instruction 2: expected KILL_PROCESS %#x, got %#x", unix.SECCOMP_RET_KILL_PROCESS, filter[2].K)
	}

	// Verify all intercepted syscall numbers are present.
	found := make(map[uint32]bool)
	for i := 4; i < 4+len(syscalls); i++ {
		found[filter[i].K] = true
	}
	for _, nr := range syscalls {
		if !found[nr] {
			t.Errorf("syscall nr=%d not in filter", nr)
		}
	}

	// Verify ALLOW and USER_NOTIF returns.
	allowIdx := 4 + len(syscalls)
	notifIdx := allowIdx + 1
	if filter[allowIdx].K != unix.SECCOMP_RET_ALLOW {
		t.Errorf("instruction %d: expected ALLOW %#x, got %#x", allowIdx, unix.SECCOMP_RET_ALLOW, filter[allowIdx].K)
	}
	if filter[notifIdx].K != unix.SECCOMP_RET_USER_NOTIF {
		t.Errorf("instruction %d: expected USER_NOTIF %#x, got %#x", notifIdx, unix.SECCOMP_RET_USER_NOTIF, filter[notifIdx].K)
	}

	// Verify all jumps target USER_NOTIF.
	for i := 4; i < 4+len(syscalls); i++ {
		expectedJt := uint8(notifIdx - i - 1)
		if filter[i].Jt != expectedJt {
			t.Errorf("instruction %d: expected Jt=%d (-> USER_NOTIF), got %d", i, expectedJt, filter[i].Jt)
		}
		if filter[i].Jf != 0 {
			t.Errorf("instruction %d: expected Jf=0 (fall through), got %d", i, filter[i].Jf)
		}
	}
}

func TestSerializeFilter(t *testing.T) {
	filter := buildNotifFilter(auditArch, interceptedSyscalls)
	buf := serializeFilter(filter)
	if len(buf) != len(filter)*8 {
		t.Fatalf("expected %d bytes, got %d", len(filter)*8, len(buf))
	}
}

func TestParseMountInfo_Empty(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "mountinfo")
	err := os.WriteFile(f, []byte(""), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	got := parseMountInfo(f, "/workdir")
	if !got["/proc/sys"] {
		t.Error("expected /proc/sys to be protected")
	}
	if !got["/proc/1"] {
		t.Error("expected /proc/1 to be protected")
	}
	if len(got) != 2 {
		t.Errorf("expected 2 protected paths, got %d", len(got))
	}
}

func TestParseMountInfo_ROBindUnderWorkdir(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "mountinfo")
	content := `25 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
100 25 8:1 /workdir/.env /workdir/.env ro,relatime - ext4 /dev/sda1 rw
101 25 8:1 /workdir/.git/hooks /workdir/.git/hooks ro,relatime - ext4 /dev/sda1 rw
102 25 0:5 / /workdir/.npmrc ro,relatime - devtmpfs /dev/null rw
103 25 8:1 /workdir /workdir rw,relatime - ext4 /dev/sda1 rw
`
	err := os.WriteFile(f, []byte(content), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	got := parseMountInfo(f, "/workdir")

	expected := map[string]bool{
		"/proc/sys":           true,
		"/workdir/.env":       true,
		"/workdir/.git/hooks": true,
		"/workdir/.npmrc":     true,
	}
	for path := range expected {
		if !got[path] {
			t.Errorf("expected %s to be protected", path)
		}
	}

	if got["/workdir"] {
		t.Error("/workdir should not be protected (it is the workdir itself)")
	}
}

func TestParseMountInfo_DevNullMount(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "mountinfo")
	content := `25 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
200 25 0:6 / /workdir/.envrc rw,relatime - devtmpfs /dev/null rw
`
	err := os.WriteFile(f, []byte(content), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	got := parseMountInfo(f, "/workdir")
	if !got["/workdir/.envrc"] {
		t.Error("expected /workdir/.envrc to be protected (devnull mount)")
	}
}

func TestParseMountInfo_RWNotProtected(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "mountinfo")
	content := `25 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
300 25 8:1 /workdir/src /workdir/src rw,relatime - ext4 /dev/sda1 rw
`
	err := os.WriteFile(f, []byte(content), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	got := parseMountInfo(f, "/workdir")
	if got["/workdir/src"] {
		t.Error("/workdir/src should not be protected (RW, not devnull)")
	}
}

func TestParseMountInfo_MissingFile(t *testing.T) {
	got := parseMountInfo("/nonexistent/mountinfo", "/workdir")
	if !got["/proc/sys"] {
		t.Error("expected /proc/sys even when file missing")
	}
	if len(got) != 2 {
		t.Errorf("expected 2 protected paths on error, got %d", len(got))
	}
}

func TestParseMountInfo_Proc1AlwaysProtected(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "mountinfo")
	err := os.WriteFile(f, []byte(""), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	got := parseMountInfo(f, "/workdir")
	if !got["/proc/1"] {
		t.Error("expected /proc/1 to be protected")
	}
	// Verify sub-paths are also protected via isProtected.
	if !isProtected("/proc/1/mem", got) {
		t.Error("expected /proc/1/mem to be protected (sub-path of /proc/1)")
	}
	if !isProtected("/proc/1/maps", got) {
		t.Error("expected /proc/1/maps to be protected")
	}
}

func TestParseMountInfo_ProcSysAlwaysProtected(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "mountinfo")
	content := `25 1 0:1 / /proc/sys ro,relatime - proc proc rw
`
	err := os.WriteFile(f, []byte(content), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	got := parseMountInfo(f, "/workdir")
	if !got["/proc/sys"] {
		t.Error("expected /proc/sys to be protected")
	}
}

func TestIsProtected(t *testing.T) {
	protected := map[string]bool{
		"/proc/sys":           true,
		"/workdir/.env":       true,
		"/workdir/.git/hooks": true,
	}

	tests := []struct {
		path string
		want bool
	}{
		{"/proc/sys", true},
		{"/proc/sys/kernel/core_pattern", true},
		{"/proc/sys/net", true},
		{"/workdir/.env", true},
		{"/workdir/.git/hooks", true},
		{"/workdir/.git/hooks/pre-commit", true},
		{"/workdir/src", false},
		{"/tmp/foo", false},
		{"/proc/sys/../sys/kernel", true},
		{".", false},
	}
	for _, tt := range tests {
		got := isProtected(tt.path, protected)
		if got != tt.want {
			t.Errorf("isProtected(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestIsSubPath(t *testing.T) {
	tests := []struct {
		base, path string
		want       bool
	}{
		{"/a", "/a", true},
		{"/a", "/a/b", true},
		{"/a", "/a/b/c", true},
		{"/a", "/b", false},
		{"/a", "/ab", false},
		{"/a/b", "/a", false},
		{"/a", "/", false},
		{"/", "/a", true},
	}
	for _, tt := range tests {
		got := isSubPath(tt.base, tt.path)
		if got != tt.want {
			t.Errorf("isSubPath(%q, %q) = %v, want %v", tt.base, tt.path, got, tt.want)
		}
	}
}
