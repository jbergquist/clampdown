// SPDX-License-Identifier: GPL-3.0-only

package network

import (
	"context"
	"log/slog"
	"net"
	"strings"
)

// ResolveAllowlist resolves domains to IPs using the host's DNS resolver.
// IPs and CIDRs pass through unchanged. Used at startup to pre-resolve
// the agent's static allowlist before passing to the sidecar as env var.
func ResolveAllowlist(domains []string) []string {
	var out []string

	// Pure-Go resolver bypasses system resolver caching (nscd,
	// systemd-resolved). Each LookupHost call makes a fresh DNS query,
	// which is essential for catching DNS round-robin rotation (e.g.
	// ghcr.io alternates between two IPs per query).
	resolver := &net.Resolver{PreferGo: true}

	for _, entry := range domains {
		// Already an IP — pass through.
		if net.ParseIP(entry) != nil {
			out = append(out, entry)
			continue
		}
		// CIDR — validate and reject overly broad ranges.
		_, cidr, cidrErr := net.ParseCIDR(entry)
		if cidrErr == nil {
			ones, _ := cidr.Mask.Size()
			if ones < 4 {
				slog.Warn("overly broad CIDR in allowlist, skipping", "cidr", entry)
				continue
			}
			out = append(out, entry)
			continue
		}
		// Domain — query multiple times to collect all round-robin IPs.
		seen := make(map[string]bool)
		for range 20 {
			addrs, err := resolver.LookupHost(context.Background(), entry)
			if err != nil {
				continue
			}
			for _, a := range addrs {
				if net.ParseIP(a) != nil && !seen[a] {
					seen[a] = true
					out = append(out, a)
				}
			}
		}
		if len(seen) == 0 {
			slog.Warn("cannot resolve host", "host", entry)
		}
	}

	return out
}

// ClassifyIPs splits resolved IPs into IPv4 and IPv6 buckets.
func ClassifyIPs(entries []string) ([]string, []string) {
	var ip4s, ip6s []string
	for _, entry := range entries {
		if strings.Contains(entry, ":") {
			ip6s = append(ip6s, entry)
		} else {
			ip4s = append(ip4s, entry)
		}
	}
	return ip4s, ip6s
}
