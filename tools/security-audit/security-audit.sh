#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# security-audit-api.sh - Security audit using Claude CLI via clampdown
# =============================================================================

usage()
{
	cat << 'EOF'
Usage: security-audit.sh [OPTIONS]

Runs one security audit cycle using Claude CLI.

Options:
    --file FILE   Audit a specific file (skip selection phase)
    --dry-run     Print prompts without calling Claude
    -h, --help    Show this help text

Environment:
    PROJECT_DIR          Codebase root (default: current directory)
    REPORT_ROOT          Report root path (default: <project>/reports)
    MODEL                Model to use (default: claude-opus-4-5)
    EFFORT               Reasoning effort (default: max)
    FILE_PATTERNS        File extensions to scan (default: *.c *.h *.py *.js *.ts *.go *.rs *.java)
EOF
}

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
PROJECT_DIR="${PROJECT_DIR:-$(pwd)}"
REPORT_ROOT="${REPORT_ROOT:-$PROJECT_DIR/reports}"
RUNS_DIR="${RUNS_DIR:-$PROJECT_DIR/runs}"
MODEL="${MODEL:-claude-opus-4-5}"
EFFORT="${EFFORT:-max}"
FILE_PATTERNS="${FILE_PATTERNS:-*.c *.h *.py *.js *.ts *.go *.rs *.java}"

VALIDATED_DIR="$REPORT_ROOT/validated"
PROGRESS_FILE="$REPORT_ROOT/.audit-progress"
DRY_RUN=false
TARGET_FILE=""

while [[ $# -gt 0 ]]; do
	case "$1" in
		--file)
			TARGET_FILE="$2"
			shift 2
			;;
		--dry-run)
			DRY_RUN=true
			shift
			;;
		-h | --help)
			usage
			exit 0
			;;
		*)
			echo "Unknown: $1"
			exit 1
			;;
	esac
done

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
log()
{
	echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"
}

ensure_dirs()
{
	mkdir -p "$VALIDATED_DIR" "$RUNS_DIR"
}

get_file_list()
{
	# Skip hidden directories, match common source files
	find "$PROJECT_DIR" \
		-type d -name '.*' -prune -o \
		-type f \( \
			-name '*.c' -o -name '*.h' -o -name '*.py' -o -name '*.js' -o \
			-name '*.ts' -o -name '*.go' -o -name '*.rs' -o -name '*.java' \
		\) -print 2>/dev/null | \
		sed "s|^$PROJECT_DIR/||" | head -200 | sort
}

get_validated_summary()
{
	if [[ -d $VALIDATED_DIR ]] && compgen -G "$VALIDATED_DIR/*.md" > /dev/null; then
		local count=0
		for f in "$VALIDATED_DIR"/*.md; do
			count=$((count + 1))
			echo "=== EXISTING FINDING #$count: $(basename "$f") ==="
			# Get title, affected code, and summary for duplicate detection
			head -60 "$f"
			echo ""
			echo "---"
			echo ""
		done
		echo "(Total existing validated findings: $count)"
	else
		echo "(No validated findings yet - this is the first run)"
	fi
}

# -----------------------------------------------------------------------------
# Claude CLI Call
# -----------------------------------------------------------------------------
call_claude()
{
	local system_prompt="$1"
	local user_prompt="$2"
	local output_file="$3"

	# Combine system + user into a single prompt for CLI
	local full_prompt="$system_prompt

---

$user_prompt"

	if [[ $DRY_RUN == "true" ]]; then
		log "[DRY-RUN] Would call Claude with ${#full_prompt} char prompt"
		echo "$full_prompt" > "$output_file.prompt.txt"
		echo '{"dry_run": true}' > "$output_file"
		return 0
	fi

	# Call Claude via clampdown with prompt as argument
	clampdown claude -- \
		--dangerously-skip-permissions \
		--model "$MODEL" \
		--effort "$EFFORT" \
		--print \
		--output-format text \
		-p "$full_prompt" > "$output_file" 2>&1 || {
		log "Claude returned non-zero, check $output_file"
		return 1
	}
}

# -----------------------------------------------------------------------------
# Selection Phase
# -----------------------------------------------------------------------------
run_selection()
{
	local run_dir="$1"
	local file_list="$2"
	local validated_summary="$3"

	local system="You are a security researcher selecting the next audit target. Output valid JSON only."

	local user
	user=$(
		cat << EOF
## Codebase files (sample)
$file_list

## Already validated findings
$validated_summary

## Task
Select ONE file and ONE specific vulnerability target to investigate.

Vulnerability classes to consider:

**Classic Web/App:**
- Injection (SQL, Command, LDAP, XPath)
- Authentication/Session issues
- Access Control flaws
- XSS, CSRF, SSRF
- Insecure Deserialization
- Path Traversal

**Memory Safety:**
- Buffer Overflow, Use-After-Free, Double-Free
- Integer Overflow/Underflow, Type Confusion
- Uninitialized Memory, Out-of-Bounds R/W
- Race Conditions (TOCTOU)

**Sandbox/Container Escape:**
- Container breakout (cgroups, namespaces, capabilities)
- seccomp/AppArmor/SELinux bypass
- /proc or /sys abuse
- Device file access (/dev/mem, /dev/kmem, /dev/sda)
- Mount namespace escapes
- Privileged container misuse
- Volume mount path traversal to host
- Unix socket exposure (docker.sock, podman.sock)
- runc/crun/containerd vulnerabilities

**Kernel/Privilege Escalation:**
- Syscall vulnerabilities
- ioctl handler bugs
- Netfilter/eBPF exploits
- Capability misuse (CAP_SYS_ADMIN, CAP_NET_RAW, etc.)
- Kernel module loading
- SUID/SGID binary abuse
- Dirty Pipe/COW style bugs

**Lateral Movement:**
- Credential harvesting from env/files/memory
- SSH key theft or agent hijacking
- Service account token abuse (Kubernetes)
- Network pivoting via exposed services
- Cloud metadata service (169.254.169.254) access
- Internal API abuse

**Cryptographic:**
- Weak RNG, hardcoded secrets
- Key material exposure
- Downgrade attacks

Output JSON:
{
  "selected_file": "path/to/file",
  "investigation_target": "specific area",
  "rationale": "why this is promising",
  "differs_from_existing": "how it's not a duplicate"
}
EOF
	)

	call_claude "$system" "$user" "$run_dir/selection.json"
}

# -----------------------------------------------------------------------------
# Analysis Phase
# -----------------------------------------------------------------------------
run_analysis()
{
	local run_dir="$1"
	local validated_summary="$2"

	local selected_file target rationale
	selected_file=$(jq -r '.selected_file // empty' "$run_dir/selection.json" 2> /dev/null || echo "")
	target=$(jq -r '.investigation_target // empty' "$run_dir/selection.json" 2> /dev/null || echo "")
	rationale=$(jq -r '.rationale // empty' "$run_dir/selection.json" 2> /dev/null || echo "")

	if [[ -z $selected_file ]]; then
		log "ERROR: No file selected"
		return 1
	fi

	log "Analyzing: $selected_file -> $target"

	local file_content=""
	[[ -f "$PROJECT_DIR/$selected_file" ]] && file_content=$(head -500 "$PROJECT_DIR/$selected_file")

	local system="You are a security auditor writing CVE-style vulnerability reports. Be thorough and precise."

	local user
	user=$(
		cat << EOF
## Target
File: $selected_file
Focus: $target
Selection rationale: $rationale

## Code
\`\`\`
$file_content
\`\`\`

## Existing findings (avoid duplicates)
$validated_summary

## Task
Analyze for security vulnerabilities. Pay special attention to:
- Sandbox/container escape vectors (namespace, cgroup, capability, mount abuse)
- Privilege escalation paths (SUID, capabilities, kernel interfaces)
- Lateral movement opportunities (credential exposure, network pivoting)
- Host breakout from containerized contexts

If found, write a report:

# [Title]

## Summary
Brief description.

## Severity
Critical/High/Medium/Low + CVSS if possible

## CWE
CWE-XXX: Name

## Attack Surface
How an attacker reaches this code (container, network, local user, etc.)

## Affected Code
File and lines

## Technical Details
How it works. For escape/escalation bugs, describe:
- What boundary is crossed (container->host, user->root, sandbox->system)
- What primitives are gained (arbitrary read/write, code exec, capability)

## Proof of Concept
Exploitation steps or code. Include:
- Prerequisites (container config, kernel version, etc.)
- Concrete commands or code
- Expected vs exploited behavior

## Impact
What attacker achieves. Specify:
- Pre-exploitation context (unprivileged container, sandboxed process, etc.)
- Post-exploitation context (host root, kernel code exec, etc.)

## Remediation
How to fix. Include:
- Code changes
- Configuration hardening (seccomp, AppArmor, capabilities to drop)
- Architectural mitigations

---
If no vulnerability found, explain what was checked and why no issue exists.
EOF
	)

	call_claude "$system" "$user" "$run_dir/report.md"
}

# -----------------------------------------------------------------------------
# Validation Phase
# -----------------------------------------------------------------------------
run_validation()
{
	local run_dir="$1"
	local validated_summary="$2"

	local report
	report=$(cat "$run_dir/report.md")

	local system="You are a strict security validator. Your job is to REJECT false positives and duplicates. Be skeptical. Only output valid JSON."

	local user
	user=$(
		cat << EOF
## Candidate Report to Validate
$report

## ALL Existing Validated Findings (you MUST check for duplicates against these)
$validated_summary

---

## YOUR VALIDATION TASKS (complete ALL of these)

### Task 1: Duplicate Check (CRITICAL - do this FIRST)
Compare this candidate against EVERY existing validated finding listed above.
A finding is a DUPLICATE if ANY of these match:
- Same file AND same vulnerable function/code path
- Same vulnerability class in the same component (e.g., both are buffer overflows in the parser)
- Same root cause, even if the description uses different words
- Overlapping exploitation path that would be fixed by the same patch

If ANY existing finding covers this issue, even partially → REJECT as duplicate.

### Task 2: Verify the Bug Actually Exists
The report MUST have:
- [ ] Exact code location (file path + line numbers)
- [ ] The actual vulnerable code shown
- [ ] Concrete trigger (specific input/command, not "an attacker could...")
- [ ] Real vulnerability, not just "risky code pattern"

REJECT if you see these red flags:
- Vague language ("may lead to", "could potentially", "if an attacker...")
- No specific line numbers
- Speculation without demonstrated exploitation
- "Recommendation" or "hardening" disguised as a vulnerability
- The claimed bug doesn't actually exist in the shown code
- Defense-in-depth suggestion, not actual vulnerability

### Task 3: Verify It's Actually Exploitable
- [ ] The vulnerable code path is reachable (not dead code, not behind admin auth)
- [ ] The prerequisites are realistic (default config, common deployment)
- [ ] Container escapes: must work WITHOUT --privileged (unless that's the bug)
- [ ] Kernel bugs: must affect kernel >= 5.x or current LTS
- [ ] The PoC steps would actually work if executed

### Task 4: Honest Severity Check
- Is this really Critical/High severity, or is the report exaggerating?
- Would this get a CVE, or is it a hardening suggestion?
- What's the realistic impact (not the theoretical worst-case)?

---

## Output Format (JSON only, no markdown)
{
  "decision": "ACCEPT" or "REJECT",

  "duplicate_check": {
    "is_duplicate": true or false,
    "matches_existing": "filename of matching finding, or null",
    "reasoning": "explain the comparison"
  },

  "bug_exists_check": {
    "has_exact_location": true or false,
    "has_concrete_trigger": true or false,
    "is_real_vulnerability": true or false,
    "reasoning": "explain why this is/isn't a real bug"
  },

  "exploitability_check": {
    "code_is_reachable": true or false,
    "prereqs_are_realistic": true or false,
    "poc_would_work": true or false,
    "reasoning": "explain exploitability"
  },

  "severity": "Critical/High/Medium/Low/Invalid",
  "confidence": "high/medium/low",
  "summary": "one sentence final verdict"
}

IMPORTANT: Default to REJECT. Only ACCEPT if ALL THREE checks pass:
1. NOT a duplicate
2. Bug demonstrably EXISTS
3. Bug is realistically EXPLOITABLE
EOF
	)

	call_claude "$system" "$user" "$run_dir/validation.json"
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
main()
{
	ensure_dirs

	local run_id
	run_id=$(date -u +%Y%m%dT%H%M%SZ)-$$
	local run_dir="$RUNS_DIR/$run_id"
	mkdir -p "$run_dir"

	log "Run: $run_id"
	log "Model: $MODEL (effort: $EFFORT)"
	log "Project: $PROJECT_DIR"

	local validated_summary
	validated_summary=$(get_validated_summary)

	# If a specific file is targeted, skip selection phase
	if [[ -n $TARGET_FILE ]]; then
		log "Target file: $TARGET_FILE (skipping selection)"

		# Create a synthetic selection result
		cat > "$run_dir/selection.json" << EOF
{
  "selected_file": "$TARGET_FILE",
  "investigation_target": "comprehensive security audit of this file",
  "rationale": "systematic file-by-file audit",
  "differs_from_existing": "covering all files systematically"
}
EOF
	else
		local file_list
		file_list=$(get_file_list)
		log "Files: $(echo "$file_list" | wc -l)"

		log "Step 1: Selection"
		run_selection "$run_dir" "$file_list" "$validated_summary"
	fi

	log "Step 2: Analysis"
	run_analysis "$run_dir" "$validated_summary"

	log "Step 3: Validation"
	run_validation "$run_dir" "$validated_summary"

	# Check result
	local decision
	decision=$(jq -r '.decision // "REJECT"' "$run_dir/validation.json" 2> /dev/null || echo "REJECT")

	if [[ $decision == "ACCEPT" ]]; then
		local ts severity
		ts=$(date -u +%Y%m%dT%H%M%SZ)
		severity=$(jq -r '.severity // "Unknown"' "$run_dir/validation.json" 2> /dev/null || echo "Unknown")
		cp "$run_dir/report.md" "$VALIDATED_DIR/${ts}.md"
		log "ACCEPTED [$severity] -> $VALIDATED_DIR/${ts}.md"
	else
		local summary is_dup
		summary=$(jq -r '.summary // "no reason"' "$run_dir/validation.json" 2> /dev/null || echo "")
		is_dup=$(jq -r '.duplicate_check.is_duplicate // false' "$run_dir/validation.json" 2> /dev/null || echo "false")
		if [[ $is_dup == "true" ]]; then
			local matches
			matches=$(jq -r '.duplicate_check.matches_existing // "unknown"' "$run_dir/validation.json" 2> /dev/null || echo "")
			log "REJECTED [DUPLICATE of $matches]: $summary"
		else
			log "REJECTED: $summary"
		fi
	fi

	log "Done. Artifacts in $run_dir"
}

main "$@"
