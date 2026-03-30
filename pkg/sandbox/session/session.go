// SPDX-License-Identifier: GPL-3.0-only

package session

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"text/tabwriter"
	"time"

	"github.com/89luca89/clampdown/pkg/container"
	"github.com/89luca89/clampdown/pkg/sandbox"
)

// Session holds display info for a running sandbox session.
type Session struct {
	Agent       string
	AgentPolicy string
	ID          string
	PodPolicy   string
	State       string
	Uptime      time.Duration
	Workdir     string
}

// List returns all sandbox sessions (running and stopped).
func List(ctx context.Context, rt container.Runtime) ([]Session, error) {
	infos, err := rt.List(ctx, map[string]string{
		"clampdown":      sandbox.AppName,
		"clampdown.role": "sidecar",
	})
	if err != nil {
		return nil, err
	}
	sessions := make([]Session, 0, len(infos))
	for _, info := range infos {
		uptime := time.Duration(0)
		if info.StartedAt > 0 {
			uptime = time.Since(time.Unix(info.StartedAt, 0))
		}
		sessions = append(sessions, Session{
			Agent:       info.Labels["clampdown.agent"],
			AgentPolicy: info.Labels["clampdown.agent_policy"],
			ID:          info.Labels["clampdown.session"],
			PodPolicy:   info.Labels["clampdown.pod_policy"],
			State:       info.State,
			Uptime:      uptime,
			Workdir:     info.Labels["clampdown.workdir"],
		})
	}
	return sessions, nil
}

// Container identifies a container in a session by name and role.
type Container struct {
	Name string
	Role string // "sidecar", "proxy", or agent name
}

// FindContainers returns all containers in a session with their roles.
func FindContainers(ctx context.Context, rt container.Runtime, sessionID string) ([]Container, error) {
	infos, err := rt.List(ctx, map[string]string{
		"clampdown":         sandbox.AppName,
		"clampdown.session": sessionID,
	})
	if err != nil {
		return nil, err
	}
	if len(infos) == 0 {
		return nil, fmt.Errorf("no containers found for session %s", sessionID)
	}
	ctrs := make([]Container, len(infos))
	for i, info := range infos {
		ctrs[i] = Container{
			Name: info.Name,
			Role: info.Labels["clampdown.role"],
		}
	}
	return ctrs, nil
}

// FindSidecar resolves a session ID to a sidecar container name.
func FindSidecar(ctx context.Context, rt container.Runtime, sessionID string) (string, error) {
	ctrs, err := FindContainers(ctx, rt, sessionID)
	if err != nil {
		return "", err
	}
	for _, c := range ctrs {
		if c.Role == "sidecar" {
			return c.Name, nil
		}
	}
	return "", fmt.Errorf("no sidecar found for session %s", sessionID)
}

// FindAgent resolves a session ID to an agent container name.
func FindAgent(ctx context.Context, rt container.Runtime, sessionID string) (string, error) {
	ctrs, err := FindContainers(ctx, rt, sessionID)
	if err != nil {
		return "", err
	}
	for _, c := range ctrs {
		if c.Role != "sidecar" && c.Role != "proxy" {
			return c.Name, nil
		}
	}
	return "", fmt.Errorf("no agent found for session %s", sessionID)
}

// IsRunning checks if a specific container is in running state.
func IsRunning(ctx context.Context, rt container.Runtime, sessionID, name string) (bool, error) {
	infos, err := rt.List(ctx, map[string]string{
		"clampdown":         sandbox.AppName,
		"clampdown.session": sessionID,
	})
	if err != nil {
		return false, err
	}
	for _, info := range infos {
		if info.Name == name {
			return info.State == "running", nil
		}
	}
	return false, nil
}

// Stop stops all containers for a session (agent → proxy → sidecar).
func Stop(ctx context.Context, rt container.Runtime, sessionID string) error {
	infos, err := rt.List(ctx, map[string]string{
		"clampdown":         sandbox.AppName,
		"clampdown.session": sessionID,
	})
	if err != nil {
		return err
	}
	if len(infos) == 0 {
		return fmt.Errorf("no containers found for session %s", sessionID)
	}

	// Stop order: agents → proxies → sidecars.
	var agents, proxies, sidecars []string
	for _, info := range infos {
		switch info.Labels["clampdown.role"] {
		case "sidecar":
			sidecars = append(sidecars, info.Name)
		case "proxy":
			proxies = append(proxies, info.Name)
		default:
			agents = append(agents, info.Name)
		}
	}

	var all []string
	all = append(all, agents...)
	all = append(all, proxies...)
	all = append(all, sidecars...)
	err = rt.Stop(ctx, all...)
	if err != nil {
		return fmt.Errorf("stop containers: %w", err)
	}
	slog.Info("stopped session containers", "count", len(all), "session", sessionID)
	return nil
}

// Delete removes all stopped containers for a session. Returns an error
// if any container is still running.
func Delete(ctx context.Context, rt container.Runtime, sessionID string) error {
	infos, err := rt.List(ctx, map[string]string{
		"clampdown":         sandbox.AppName,
		"clampdown.session": sessionID,
	})
	if err != nil {
		return err
	}
	if len(infos) == 0 {
		return fmt.Errorf("no containers found for session %s", sessionID)
	}

	// Check that all containers are stopped.
	for _, info := range infos {
		if info.State == "running" {
			return fmt.Errorf("session %s has running containers — use 'stop' first", sessionID)
		}
	}

	// Remove order: agents → proxies → sidecars.
	var agents, proxies, sidecars []string
	for _, info := range infos {
		switch info.Labels["clampdown.role"] {
		case "sidecar":
			sidecars = append(sidecars, info.Name)
		case "proxy":
			proxies = append(proxies, info.Name)
		default:
			agents = append(agents, info.Name)
		}
	}

	var all []string
	all = append(all, agents...)
	all = append(all, proxies...)
	all = append(all, sidecars...)
	err = rt.Remove(ctx, all...)
	if err != nil {
		return fmt.Errorf("remove containers: %w", err)
	}
	slog.Info("removed session containers", "count", len(all), "session", sessionID)
	return nil
}

// Print writes a formatted session table to stdout.
func Print(sessions []Session) {
	if len(sessions) == 0 {
		fmt.Fprintln(os.Stdout, "No sessions.")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SESSION\tAGENT\tWORKDIR\tSTATUS\tAGENTNET\tPODNET\tUPTIME")
	for _, s := range sessions {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			s.ID, s.Agent, s.Workdir, s.State, s.AgentPolicy, s.PodPolicy, FormatDuration(s.Uptime))
	}
	w.Flush()
}

func FormatDuration(d time.Duration) string {
	d = d.Truncate(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%dm", h, m)
	}
	if m > 0 {
		return fmt.Sprintf("%dm", m)
	}
	return "<1m"
}
