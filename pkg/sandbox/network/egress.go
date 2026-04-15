// SPDX-License-Identifier: GPL-3.0-only

package network

import (
	"context"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"time"
)

// Public DNS servers to query for diverse round-robin results.
// CDNs like GitHub/Cloudflare return different IPs to different resolvers.
var dnsServers = []string{
	"",                          // system resolver (empty = default)
	"1.1.1.1:53",                // Cloudflare (IPv4)
	"[2606:4700:4700::1111]:53", // Cloudflare (IPv6)
	"8.8.8.8:53",                // Google (IPv4)
	"[2001:4860:4860::8888]:53", // Google (IPv6)
	"9.9.9.9:53",                // Quad9 (IPv4)
	"[2620:fe::fe]:53",          // Quad9 (IPv6)
	"208.67.222.222:53",         // OpenDNS (IPv4)
	"[2620:119:35::35]:53",      // OpenDNS (IPv6)
}

// ResolveAllowlist resolves domains to IPs using multiple DNS resolvers.
// IPs and CIDRs pass through unchanged. Used at startup to pre-resolve
// the agent's static allowlist before passing to the sidecar as env var.
//
// Queries each domain against multiple public DNS servers to capture
// geographically diverse round-robin IPs from CDNs.
func ResolveAllowlist(domains []string) []string {
	var out []string

	// Separate passthrough entries (IPs, CIDRs) from domains needing resolution.
	var toResolve []string
	for _, entry := range domains {
		if net.ParseIP(entry) != nil {
			out = append(out, entry)
			continue
		}
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
		toResolve = append(toResolve, entry)
	}

	// Resolve all domains in parallel.
	resolved := make([][]string, len(toResolve))

	var wg sync.WaitGroup
	for i, domain := range toResolve {
		wg.Go(func() {
			resolved[i] = resolveDomain(domain)
		})
	}
	wg.Wait()

	for i, ips := range resolved {
		if len(ips) == 0 {
			slog.Warn("cannot resolve host", "host", toResolve[i])
			continue
		}
		out = append(out, ips...)
		slog.Debug("resolved domain", "domain", toResolve[i], "ips", len(ips))
	}

	slices.Sort(out)
	return slices.Compact(out)
}

// resolveDomain queries all DNS servers in parallel, each 20 times
// sequentially to catch round-robin rotation.
func resolveDomain(domain string) []string {
	perServer := make([][]string, len(dnsServers))

	var wg sync.WaitGroup
	for i, server := range dnsServers {
		wg.Go(func() {
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

			var ips []string
			for range 20 {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				addrs, err := resolver.LookupHost(ctx, domain)
				cancel()
				if err != nil {
					continue
				}
				for _, a := range addrs {
					if net.ParseIP(a) != nil {
						ips = append(ips, a)
					}
				}
			}
			perServer[i] = ips
		})
	}
	wg.Wait()

	var all []string
	for _, ips := range perServer {
		all = append(all, ips...)
	}
	return all
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
