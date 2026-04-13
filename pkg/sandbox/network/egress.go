// SPDX-License-Identifier: GPL-3.0-only

package network

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"time"
)

// Public DNS servers to query for diverse round-robin results.
// CDNs like GitHub/Cloudflare return different IPs to different resolvers.
var dnsServers = []string{
	"",                  // system resolver (empty = default)
	"1.1.1.1:53",        // Cloudflare
	"8.8.8.8:53",        // Google
	"9.9.9.9:53",        // Quad9
	"208.67.222.222:53", // OpenDNS
}

// ResolveAllowlist resolves domains to IPs using multiple DNS resolvers.
// IPs and CIDRs pass through unchanged. Used at startup to pre-resolve
// the agent's static allowlist before passing to the sidecar as env var.
//
// Queries each domain against multiple public DNS servers to capture
// geographically diverse round-robin IPs from CDNs.
func ResolveAllowlist(domains []string) []string {
	var out []string

	for _, entry := range domains {
		// Already an IP — pass through.
		if net.ParseIP(entry) != nil {
			out = append(out, entry)
			continue
		}
		// CIDR — validate and reject overly broad or non-standard ranges.
		_, cidr, cidrErr := net.ParseCIDR(entry)
		if cidrErr == nil {
			ones, bits := cidr.Mask.Size()
			if bits == 0 {
				slog.Warn("non-standard CIDR mask in allowlist, skipping", "cidr", entry)
				continue
			}
			if ones < 4 {
				slog.Warn("overly broad CIDR in allowlist, skipping", "cidr", entry)
				continue
			}
			out = append(out, entry)
			continue
		}
		// Domain — query multiple DNS servers, multiple times each.
		seen := make(map[string]bool)
		for _, server := range dnsServers {
			resolver := &net.Resolver{PreferGo: true}
			if server != "" {
				resolver = &net.Resolver{
					PreferGo: true,
					Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
						d := net.Dialer{Timeout: 2 * time.Second}
						return d.DialContext(ctx, "udp", server)
					},
				}
			}
			// Query each server multiple times to catch rotation.
			for range 20 {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				addrs, err := resolver.LookupHost(ctx, entry)
				cancel()
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
		}
		if len(seen) == 0 {
			slog.Warn("cannot resolve host", "host", entry)
			continue
		}

		slog.Debug("resolved domain", "domain", entry, "ips", len(seen))
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
