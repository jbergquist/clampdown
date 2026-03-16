// SPDX-License-Identifier: GPL-3.0-only

package sandbox

import (
	"context"
	"log/slog"
	"os"
	"regexp"
	"strings"

	"github.com/89luca89/clampdown/pkg/container"
)

// dumpAuditLogs reads sidecar and proxy container logs, filters for
// clampdown: lines, and appends them to the audit file. Called before
// cleanup removes the containers so the audit trail persists on disk.
// Logs() returns --timestamps output; the runtime timestamp prefix is
// stripped so only the clampdown: embedded timestamp remains.
func dumpAuditLogs(ctx context.Context, rt container.Runtime, f *os.File, sidecar, proxy string) {
	for _, name := range []string{sidecar, proxy} {
		if name == "" {
			continue
		}
		logs, err := rt.Logs(ctx, name)
		if err != nil {
			continue
		}
		for line := range strings.SplitSeq(string(logs), "\n") {
			if line == "" {
				continue
			}
			if strings.Contains(line, "clampdown:") {
				// Strip the runtime --timestamps prefix, keep
				// only the clampdown: line with its own timestamp.
				clean := StripRuntimeTimestamp(line)
				f.WriteString(clean + "\n")
			}
		}
	}
	slog.Info("audit log written", "path", f.Name())
}

// StripRuntimeTimestamp removes the RFC3339Nano prefix that
// podman/docker --timestamps prepends to each log line
// (e.g., "2026-03-14T10:00:00.123456789Z actual content").
func StripRuntimeTimestamp(line string) string {
	// RFC3339Nano minimum: "2006-01-02T15:04:05Z" = 20 chars.
	if len(line) < 21 {
		return line
	}
	sp := strings.IndexByte(line[20:], ' ')
	if sp < 0 {
		return line
	}
	return line[20+sp+1:]
}

// ansiRe matches ANSI CSI sequences (colors, cursor, clear screen, etc.)
// and OSC sequences (terminal title, hyperlinks).
var ansiRe = regexp.MustCompile(`\x1b(?:\[[0-9;?]*[a-zA-Z~]|\][^\x07\x1b]*(?:\x07|\x1b\\))`)

// CleanTerminalLine strips ANSI escapes and replaces control characters
// (\r, \n) with spaces so each log entry stays on one line.
func CleanTerminalLine(line string) string {
	clean := ansiRe.ReplaceAllString(line, "")
	clean = strings.ReplaceAll(clean, "\r", " ")
	clean = strings.ReplaceAll(clean, "\n", " ")
	return clean
}
