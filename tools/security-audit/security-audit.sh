#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# security-audit-unified.sh - Security audit for single files or entire projects
# =============================================================================

usage()
{
	cat << 'EOF'
Usage: security-audit-unified.sh [OPTIONS]

Security audit using Claude CLI via clampdown.

Modes (pick one):
    --file FILE       Audit a single file in depth
    --project [DIR]   Audit entire project (default: current directory)

Options:
    --dry-run         Print prompts without calling Claude
    -h, --help        Show this help

Environment:
    MODEL             Model to use (default: claude-opus-4-6[1m])
    EFFORT            Reasoning effort (default: max)
    REPORT_ROOT       Report directory (default: <project>/reports)
EOF
}

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
MODEL="${MODEL:-"claude-opus-4-6[1m]"}"
EFFORT="${EFFORT:-max}"
DRY_RUN=false
MODE=""
TARGET_FILE=""
PROJECT_DIR=""

while [[ $# -gt 0 ]]; do
	case "$1" in
		--file)
			MODE="file"
			TARGET_FILE="$2"
			shift 2
			;;
		--project)
			MODE="project"
			if [[ $# -gt 1 && ! $2 =~ ^- ]]; then
				PROJECT_DIR="$2"
				shift 2
			else
				PROJECT_DIR="$(pwd)"
				shift
			fi
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
			echo "Unknown: $1" >&2
			usage
			exit 1
			;;
	esac
done

if [[ -z $MODE ]]; then
	echo "Error: Must specify --file or --project" >&2
	usage
	exit 1
fi

# Resolve paths
if [[ $MODE == "file" ]]; then
	[[ ! -f $TARGET_FILE ]] && {
		echo   "File not found: $TARGET_FILE" >&2
		exit                                            1
	}
	TARGET_FILE="$(realpath "$TARGET_FILE")"
	PROJECT_DIR="$(dirname "$TARGET_FILE")"
	# Walk up to find project root (has .git or go.mod or package.json)
	while [[ $PROJECT_DIR != "/" ]]; do
		[[ -d "$PROJECT_DIR/.git" || -f "$PROJECT_DIR/go.mod" || -f "$PROJECT_DIR/package.json" ]] && break
		PROJECT_DIR="$(dirname "$PROJECT_DIR")"
	done
	[[ $PROJECT_DIR == "/" ]] && PROJECT_DIR="$(dirname "$TARGET_FILE")"
fi

PROJECT_DIR="$(realpath "$PROJECT_DIR")"
REPORT_ROOT="${REPORT_ROOT:-$PROJECT_DIR/reports}"
RUNS_DIR="$REPORT_ROOT/runs"
VALIDATED_DIR="$REPORT_ROOT/validated"

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

get_validated_summary()
{
	if [[ -d $VALIDATED_DIR ]] && compgen -G "$VALIDATED_DIR/*.md" > /dev/null 2>&1; then
		local count=0
		for f in "$VALIDATED_DIR"/*.md; do
			count=$((count + 1))
			echo "=== EXISTING FINDING #$count: $(basename "$f") ==="
			head -60 "$f"
			echo -e "\n---\n"
		done
		echo "(Total existing validated findings: $count)"
	else
		echo "(No validated findings yet)"
	fi
}

call_claude()
{
	local prompt="$1"
	local output_file="$2"

	local prompt_file="${output_file}.prompt.txt"
	echo "$prompt" > "$prompt_file"

	if [[ $DRY_RUN == "true" ]]; then
		log "[DRY-RUN] Would call Claude with ${#prompt} char prompt"
		echo "(dry run)" > "$output_file"
		return 0
	fi

	"$(dirname "$0")"/../../clampdown claude \
		--sidecar-image clampdown-sidecar:latest \
		--proxy-image clampdown-proxy:latest \
		--agent-image clampdown-claude:latest \
		-- \
		--dangerously-skip-permissions \
		--model "$MODEL" \
		--effort "$EFFORT" \
		--print --output-format text --verbose \
		-p "$(cat "$prompt_file")" | tee "$output_file"
}

# -----------------------------------------------------------------------------
# Gather file list for @ imports
# -----------------------------------------------------------------------------
gather_file_imports()
{
	local mode="$1"

	if [[ $mode == "file" ]]; then
		echo "@$TARGET_FILE"
	else
		# Find all source files, output as @path for Claude import
		find "$PROJECT_DIR" \
			-type d -name '.*' -prune -o \
			-type d -name 'vendor' -prune -o \
			-type d -name 'node_modules' -prune -o \
			-type d -name '__pycache__' -prune -o \
			-type f \( \
			-name '*.c' -o -name '*.h' -o \
			-name '*.go' -o \
			-name '*.py' -o \
			-name '*.js' -o -name '*.ts' -o \
			-name '*.rs' -o \
			-name '*.java' -o \
			-name '*.rb' -o \
			-name '*.sh' \
			\) -print 2> /dev/null | sort | sed 's/^/@/'
	fi
}

# -----------------------------------------------------------------------------
# Analysis Phase
# -----------------------------------------------------------------------------
run_analysis()
{
	local run_dir="$1"
	local file_imports="$2"
	local target_desc="$3"

	local prompt
	prompt=$(
		cat << EOF
You are performing a security audit of: $target_desc

## Code to Audit
Read and analyze these files:
$file_imports

## Vulnerability Classes to Check

**Injection & Input:**
- Command injection, SQL injection, path traversal
- XSS, SSRF, XXE, template injection

**Authentication & Access:**
- Auth bypass, broken access control
- Hardcoded credentials, weak session management

**Sandbox/Container Escape:**
- Namespace/cgroup/capability abuse
- seccomp/AppArmor/SELinux bypass
- /proc, /sys, device file abuse
- Mount escapes, volume path traversal
- Unix socket exposure (docker.sock, podman.sock)
- Runtime vulnerabilities (runc, crun)

**Privilege Escalation:**
- SUID/capability misuse
- Kernel interface bugs
- Privilege boundary violations

**Memory Safety:**
- Buffer overflow, use-after-free, double-free
- Integer overflow, type confusion
- Race conditions (TOCTOU)

**Lateral Movement:**
- Credential/token/key exposure
- Cloud metadata access (169.254.169.254)
- Network pivoting

**Crypto:**
- Weak RNG, broken crypto
- Key material exposure

## Output Format

For EACH vulnerability found:

---

# [Title]

## Severity
Critical/High/Medium/Low (with CVSS if applicable)

## CWE
CWE-XXX: Name

## Location
File path and line numbers

## Description
What the vulnerability is.

## Attack Surface
How an attacker reaches this code.

## Proof of Concept
Concrete exploitation steps or code.

## Impact
What an attacker gains (be specific about privilege boundaries crossed).

## Remediation
How to fix it.

---

If NO vulnerabilities found, explain what you checked and why it appears secure.
Only report REAL, exploitable vulnerabilities - not theoretical concerns or hardening suggestions.
EOF
	)

	call_claude "$prompt" "$run_dir/report.md"
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

	local json_relpath="${run_dir#$PWD/}/validation.json"

	local prompt
	prompt=$(
		cat << EOF
You are a strict security validator. Your job is to REJECT false positives and duplicates.

## Report to Validate
$report

## Existing Validated Findings (check for duplicates)
$validated_summary

## Validation Checklist

### 1. Duplicate Check
Compare against ALL existing findings. Reject if:
- Same file AND same vulnerable code path
- Same vulnerability class in same component
- Same root cause (even with different wording)

### 2. Bug Exists Check
The report MUST have:
- Exact file path and line numbers
- Actual vulnerable code shown
- Concrete trigger (not "an attacker could...")

REJECT if you see:
- Vague language ("may lead to", "could potentially")
- No specific line numbers
- Speculation without demonstrated exploitation
- Hardening suggestion disguised as vulnerability

### 3. Exploitability Check
- Code path is reachable (not dead code)
- Prerequisites are realistic (default config)
- PoC would actually work

### 4. Severity Check
- Is the severity accurate or exaggerated?
- Would this get a CVE or is it just a suggestion?

## Output

Write a JSON file to: $json_relpath

Use your Write tool to write the file. The file must contain a JSON array with one
element per finding in the report. If the report contains no findings, write [].

Each element:
{
  "finding": 1,
  "title": "Short title of the finding",
  "decision": "ACCEPT" or "REJECT",
  "duplicate_check": {
    "is_duplicate": true/false,
    "matches_existing": "filename or null",
    "reasoning": "explanation"
  },
  "bug_exists": {
    "has_location": true/false,
    "has_concrete_trigger": true/false,
    "is_real_vulnerability": true/false,
    "reasoning": "explanation"
  },
  "exploitability": {
    "reachable": true/false,
    "realistic_prereqs": true/false,
    "poc_works": true/false,
    "reasoning": "explanation"
  },
  "severity": "Critical/High/Medium/Low/Invalid",
  "confidence": "high/medium/low",
  "summary": "one sentence verdict"
}

Default to REJECT. Only ACCEPT if ALL checks pass.
EOF
	)

	call_claude "$prompt" "$run_dir/validation.log"

	if [[ $DRY_RUN == "true" ]]; then
		return 0
	fi

	if [[ ! -f "$run_dir/validation.json" ]]; then
		log "ERROR: Model did not write $json_relpath"
		return 1
	fi

	if ! jq empty "$run_dir/validation.json" 2> /dev/null; then
		log "ERROR: $json_relpath is not valid JSON"
		return 1
	fi
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
	log "Mode: $MODE"
	log "Model: $MODEL (effort: $EFFORT)"
	log "Project: $PROJECT_DIR"
	log "Reports: $REPORT_ROOT"

	local validated_summary
	validated_summary=$(get_validated_summary)

	local file_imports target_desc file_count

	if [[ $MODE == "file" ]]; then
		local rel_path="${TARGET_FILE#$PROJECT_DIR/}"
		log "Target: $rel_path"
		target_desc="Single file: $rel_path"
		file_imports=$(gather_file_imports "file")
		file_count=1
	else
		log "Target: entire project"
		target_desc="Entire project at $PROJECT_DIR"
		file_imports=$(gather_file_imports "project")
		file_count=$(echo "$file_imports" | wc -l)
		log "Found $file_count source files"
	fi

	# Save file list for reference
	echo "$file_imports" > "$run_dir/files.txt"

	# Step 1: Analysis
	log "Step 1: Analysis"
	run_analysis "$run_dir" "$file_imports" "$target_desc"
	log "Analysis complete"

	# Step 2: Validation
	log "Step 2: Validation"
	run_validation "$run_dir" "$validated_summary"

	# Process per-finding results
	local total accepted=0 rejected=0
	total=$(jq 'length' "$run_dir/validation.json")

	if [[ $total -eq 0 ]]; then
		log "No findings in report"
	fi

	local i
	for ((i = 0; i < total; i++)); do
		local decision title severity summary
		decision=$(jq -r ".[$i].decision // \"REJECT\"" "$run_dir/validation.json")
		title=$(jq -r ".[$i].title // \"finding-$((i + 1))\"" "$run_dir/validation.json")
		severity=$(jq -r ".[$i].severity // \"Unknown\"" "$run_dir/validation.json")
		summary=$(jq -r ".[$i].summary // \"no reason\"" "$run_dir/validation.json")

		if [[ $decision == "ACCEPT" ]]; then
			accepted=$((accepted + 1))
			local slug
			slug=$(echo "$title" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/-/g; s/--*/-/g; s/^-//; s/-$//')
			local ts
			ts=$(date -u +%Y%m%dT%H%M%SZ)
			cp "$run_dir/report.md" "$VALIDATED_DIR/${ts}-${slug}.md"
			log "ACCEPTED [$severity] #$((i + 1)): $title -> ${ts}-${slug}.md"
		else
			rejected=$((rejected + 1))
			local is_dup
			is_dup=$(jq -r ".[$i].duplicate_check.is_duplicate // false" "$run_dir/validation.json")
			if [[ $is_dup == "true" ]]; then
				local matches
				matches=$(jq -r ".[$i].duplicate_check.matches_existing // \"unknown\"" "$run_dir/validation.json")
				log "REJECTED [DUPLICATE of $matches] #$((i + 1)): $title - $summary"
			else
				log "REJECTED #$((i + 1)): $title - $summary"
			fi
		fi
	done

	log "$accepted accepted, $rejected rejected out of $total findings"

	log "Done. Artifacts in $run_dir"
}

main "$@"
