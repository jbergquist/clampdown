// SPDX-License-Identifier: GPL-3.0-only

package network

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/89luca89/clampdown/pkg/container"
)

const (
	chainAgentAllow = "AGENT_ALLOW"
	chainAgentBlock = "AGENT_BLOCK"
	chainPodAllow   = "POD_ALLOW"
	chainPodBlock   = "POD_BLOCK"

	binIPT4 = "/usr/sbin/iptables"
	binIPT6 = "/usr/sbin/ip6tables"
)

var privateV4 = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"}
var privateV6 = []string{"::1/128", "fc00::/7", "fe80::/10"}

// BuildAgentFirewall creates the full agent OUTPUT chain structure via
// iptables-restore. Applied atomically in 2 calls (IPv4 + IPv6).
//
// deny mode: loopback → established → DNS (rate-limited) → private CIDRs REJECT →
//
//	per-IP TCP 443 ACCEPT → AGENT_ALLOW → terminal REJECT
//
// allow mode: loopback → established → AGENT_ALLOW → private CIDRs REJECT →
//
//	AGENT_BLOCK → terminal ACCEPT
func BuildAgentFirewall(ctx context.Context, rt container.Runtime, sidecar string, policy string, allowIPs []string) error {
	ip4s, ip6s := ClassifyIPs(allowIPs)

	for _, bin := range []string{binIPT4, binIPT6} {
		var dests, privRanges []string
		rejectType := "icmp-port-unreachable"
		restoreBin := "/usr/sbin/iptables-restore"
		if bin == binIPT6 {
			dests = ip6s
			privRanges = privateV6
			rejectType = "icmp6-port-unreachable"
			restoreBin = "/usr/sbin/ip6tables-restore"
		} else {
			dests = ip4s
			privRanges = privateV4
		}

		var r ruleBuilder
		r.table("filter")
		r.chain(chainAgentAllow, "-")
		r.chain(chainAgentBlock, "-")
		r.chain("OUTPUT", "ACCEPT") // policy ACCEPT; rules enforce deny
		r.flush("OUTPUT")
		r.add("OUTPUT", "-o lo -j ACCEPT")
		r.add("OUTPUT", "-m state --state ESTABLISHED,RELATED -j ACCEPT")

		if policy == "deny" {
			// DNS before private CIDRs: resolver may be on a private IP
			// (10.0.2.3 slirp4netns, 192.168.x.x bridge). Rate-limited
			// to throttle tunneling; excess dropped.
			r.add("OUTPUT", "-p udp --dport 53 -m limit --limit 10/s --limit-burst 20 -j ACCEPT")
			r.add("OUTPUT", "-p udp --dport 53 -j DROP")
			r.add("OUTPUT", "-p tcp --dport 53 -m limit --limit 10/s --limit-burst 20 -j ACCEPT")
			r.add("OUTPUT", "-p tcp --dport 53 -j DROP")
			for _, cidr := range privRanges {
				r.add("OUTPUT", fmt.Sprintf("! -o lo -d %s -j REJECT --reject-with %s", cidr, rejectType))
			}
			for _, dest := range dests {
				r.add("OUTPUT", fmt.Sprintf("-p tcp --dport 443 -d %s -j ACCEPT", dest))
			}
			r.add("OUTPUT", fmt.Sprintf("-j %s", chainAgentAllow))
			r.add("OUTPUT", fmt.Sprintf("-j REJECT --reject-with %s", rejectType))
		} else {
			r.add("OUTPUT", fmt.Sprintf("-j %s", chainAgentAllow))
			for _, cidr := range privRanges {
				r.add("OUTPUT", fmt.Sprintf("! -o lo -d %s -j REJECT --reject-with %s", cidr, rejectType))
			}
			r.add("OUTPUT", fmt.Sprintf("-j %s", chainAgentBlock))
			r.add("OUTPUT", "-j ACCEPT")
		}
		r.commit()

		out, err := rt.ExecStdin(ctx, sidecar, []string{restoreBin, "--noflush"}, r.bytes())
		if err != nil {
			return fmt.Errorf("%s restore: %w: %s", restoreBin, err, out)
		}
	}

	_ = rt.Log(ctx, sidecar, "firewall",
		fmt.Sprintf("BUILD agent: policy=%s allow=%s",
			policy, strings.Join(allowIPs, ",")))
	slog.Info("agent firewall built", "policy", policy, "ipv4", len(ip4s), "ipv6", len(ip6s))
	return nil
}

// BuildPodFirewall creates the full pod FORWARD chain structure via
// iptables-restore. Applied atomically in 2 calls (IPv4 + IPv6).
//
// allow mode: established → loopback → POD_ALLOW → private CIDRs DROP →
//
//	POD_BLOCK → ACCEPT
//
// deny mode: established → loopback → DNS ACCEPT → POD_ALLOW → DROP.
func BuildPodFirewall(ctx context.Context, rt container.Runtime, sidecar string, policy string) error {
	for _, bin := range []string{binIPT4, binIPT6} {
		var privRanges []string
		restoreBin := "/usr/sbin/iptables-restore"
		if bin == binIPT6 {
			privRanges = privateV6
			restoreBin = "/usr/sbin/ip6tables-restore"
		} else {
			privRanges = privateV4
		}

		var r ruleBuilder
		r.table("mangle")
		r.chain(chainPodAllow, "-")
		r.chain(chainPodBlock, "-")
		r.flush("FORWARD")
		r.add("FORWARD", "-m state --state ESTABLISHED,RELATED -j ACCEPT")
		r.add("FORWARD", "-o lo -j ACCEPT")

		if policy == "allow" {
			r.add("FORWARD", fmt.Sprintf("-j %s", chainPodAllow))
			for _, cidr := range privRanges {
				r.add("FORWARD", fmt.Sprintf("! -o lo -d %s -j DROP", cidr))
			}
			r.add("FORWARD", fmt.Sprintf("-j %s", chainPodBlock))
			r.add("FORWARD", "-j ACCEPT")
		} else {
			r.add("FORWARD", "-p udp --dport 53 -j ACCEPT")
			r.add("FORWARD", "-p tcp --dport 53 -j ACCEPT")
			r.add("FORWARD", fmt.Sprintf("-j %s", chainPodAllow))
			r.add("FORWARD", "-j DROP")
		}
		r.commit()

		out, err := rt.ExecStdin(ctx, sidecar, []string{restoreBin, "--noflush"}, r.bytes())
		if err != nil {
			return fmt.Errorf("%s restore: %w: %s", restoreBin, err, out)
		}
	}

	_ = rt.Log(ctx, sidecar, "firewall", fmt.Sprintf("BUILD pod: policy=%s", policy))
	slog.Info("pod firewall built", "policy", policy)
	return nil
}

// ruleBuilder generates iptables-restore format rules.
type ruleBuilder struct {
	buf strings.Builder
}

func (r *ruleBuilder) table(name string)              { fmt.Fprintf(&r.buf, "*%s\n", name) }
func (r *ruleBuilder) chain(name, policy string)      { fmt.Fprintf(&r.buf, ":%s %s [0:0]\n", name, policy) }
func (r *ruleBuilder) flush(chain string)             { fmt.Fprintf(&r.buf, "-F %s\n", chain) }
func (r *ruleBuilder) add(chain, rule string)         { fmt.Fprintf(&r.buf, "-A %s %s\n", chain, rule) }
func (r *ruleBuilder) commit()                        { r.buf.WriteString("COMMIT\n") }
func (r *ruleBuilder) bytes() []byte                  { return []byte(r.buf.String()) }

// AgentAllow adds ACCEPT rules to AGENT_ALLOW (filter table).
func AgentAllow(ctx context.Context, rt container.Runtime, sidecar string, targets []string, ports string) error {
	return modifyChain(ctx, rt, sidecar, "filter", chainAgentAllow, "ACCEPT", targets, ports)
}

// AgentBlock adds REJECT rules to AGENT_BLOCK (filter table).
// REJECT gives the agent immediate "connection refused" instead of a timeout.
func AgentBlock(ctx context.Context, rt container.Runtime, sidecar string, targets []string, ports string) error {
	return modifyChain(ctx, rt, sidecar, "filter", chainAgentBlock, "REJECT", targets, ports)
}

// PodAllow adds ACCEPT rules to POD_ALLOW (mangle table).
func PodAllow(ctx context.Context, rt container.Runtime, sidecar string, targets []string, ports string) error {
	return modifyChain(ctx, rt, sidecar, "mangle", chainPodAllow, "ACCEPT", targets, ports)
}

// PodBlock adds DROP rules to POD_BLOCK (mangle table).
func PodBlock(ctx context.Context, rt container.Runtime, sidecar string, targets []string, ports string) error {
	return modifyChain(ctx, rt, sidecar, "mangle", chainPodBlock, "DROP", targets, ports)
}

// ListRules prints all four dynamic chains grouped by Agent and Pods.
func ListRules(ctx context.Context, rt container.Runtime, sidecar string) error {
	fmt.Fprintln(os.Stderr, "=== Agent ===")
	allowed := listChain(ctx, rt, sidecar, "filter", chainAgentAllow)
	blocked := listChain(ctx, rt, sidecar, "filter", chainAgentBlock)
	if len(allowed) == 0 && len(blocked) == 0 {
		fmt.Fprintln(os.Stderr, "  (defaults only)")
	} else {
		printRules("Allowed", allowed)
		printRules("Blocked", blocked)
	}

	fmt.Fprintln(os.Stderr, "\n=== Pods ===")
	allowed = listChain(ctx, rt, sidecar, "mangle", chainPodAllow)
	blocked = listChain(ctx, rt, sidecar, "mangle", chainPodBlock)
	if len(allowed) == 0 && len(blocked) == 0 {
		fmt.Fprintln(os.Stderr, "  (defaults only)")
		return nil
	}

	printRules("Allowed", allowed)
	printRules("Blocked", blocked)

	return nil
}

func printRules(label string, rules []string) {
	if len(rules) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "  %s:\n", label)
	for _, r := range rules {
		fmt.Fprintf(os.Stderr, "    %s\n", r)
	}
}

// AgentReset flushes AGENT_ALLOW and AGENT_BLOCK chains.
func AgentReset(ctx context.Context, rt container.Runtime, sidecar string) error {
	return flushChains(ctx, rt, sidecar, "filter", chainAgentAllow, chainAgentBlock)
}

// PodReset flushes POD_ALLOW and POD_BLOCK chains.
func PodReset(ctx context.Context, rt container.Runtime, sidecar string) error {
	return flushChains(ctx, rt, sidecar, "mangle", chainPodAllow, chainPodBlock)
}

func flushChains(ctx context.Context, rt container.Runtime, sidecar, table string, chains ...string) error {
	for _, bin := range []string{"/usr/sbin/iptables", "/usr/sbin/ip6tables"} {
		for _, chain := range chains {
			_, err := rt.Exec(ctx, sidecar, []string{bin, "-t", table, "-F", chain}, nil)
			if err != nil {
				return fmt.Errorf("%s flush %s/%s: %w", bin, table, chain, err)
			}
		}
	}
	msg := fmt.Sprintf("RESET: table=%s chains=%v", table, chains)
	_ = rt.Log(ctx, sidecar, "firewall", msg)
	slog.Info("reset dynamic rules", "table", table)
	return nil
}

func modifyChain(
	ctx context.Context, rt container.Runtime, sidecar string,
	table, chain, verdict string,
	targets []string, ports string,
) error {
	resolved := ResolveAllowlist(targets)
	if len(resolved) == 0 {
		return fmt.Errorf("no IPs resolved for %v", targets)
	}
	ip4s, ip6s := ClassifyIPs(resolved)
	count := 0
	for _, ip := range ip4s {
		err := iptExec(ctx, rt, sidecar, "/usr/sbin/iptables", table, chain, verdict, ip, ports)
		if err != nil {
			return err
		}
		count++
	}
	for _, ip := range ip6s {
		err := iptExec(ctx, rt, sidecar, "/usr/sbin/ip6tables", table, chain, verdict, ip, ports)
		if err != nil {
			return err
		}
		count++
	}
	msg := fmt.Sprintf("%s: chain=%s targets=%s ports=%s count=%d",
		verdict, chain, strings.Join(targets, ","), ports, count)
	_ = rt.Log(ctx, sidecar, "firewall", msg)
	slog.Info("applied firewall rules",
		"verdict", verdict,
		"count", count,
		"table", table,
		"chain", chain,
		"targets", strings.Join(targets, ", "))
	return nil
}

func iptExec(
	ctx context.Context, rt container.Runtime, sidecar string,
	bin, table, chain, verdict, dest, ports string,
) error {
	args := []string{bin, "-t", table, "-A", chain, "-d", dest}
	portList := strings.Split(ports, ",")
	if len(portList) == 1 {
		args = append(args, "-p", "tcp", "--dport", portList[0])
	} else {
		args = append(args, "-p", "tcp", "-m", "multiport", "--dports", ports)
	}
	if verdict == "REJECT" {
		rejectType := "icmp-port-unreachable"
		if strings.Contains(bin, "ip6") {
			rejectType = "icmp6-port-unreachable"
		}
		args = append(args, "-j", "REJECT", "--reject-with", rejectType)
	} else {
		args = append(args, "-j", verdict)
	}
	_, err := rt.Exec(ctx, sidecar, args, nil)
	return err
}

func listChain(ctx context.Context, rt container.Runtime, sidecar, table, chain string) []string {
	var rules []string
	for _, bin := range []string{"/usr/sbin/iptables", "/usr/sbin/ip6tables"} {
		out, err := rt.Exec(ctx, sidecar, []string{
			bin, "-t", table, "-L", chain, "-n", "--line-numbers",
		}, nil)
		if err != nil {
			continue
		}
		ipVer := "IPv4"
		if strings.Contains(bin, "ip6") {
			ipVer = "IPv6"
		}
		for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
			if strings.HasPrefix(line, "Chain") || strings.HasPrefix(line, "num") || strings.TrimSpace(line) == "" {
				continue
			}
			rules = append(rules, fmt.Sprintf("[%s] %s", ipVer, line))
		}
	}
	return rules
}
