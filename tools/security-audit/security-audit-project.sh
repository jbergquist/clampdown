#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# security-audit-project.sh - Audit entire project in one pass
# =============================================================================

usage()
{
	cat << 'EOF'
Usage: security-audit-project.sh [OPTIONS] [PROJECT_DIR]

Audits an entire project holistically (not file-by-file).
Claude analyzes the full codebase and produces a comprehensive security report.

Options:
    --dry-run     Print prompts without calling Claude
    -h, --help    Show this help text

Environment:
    MODEL                Model to use (default: claude-opus-4-5)
    EFFORT               Reasoning effort (default: max)
    FILE_PATTERNS        File extensions (default: *.c *.h *.py *.js *.ts *.go *.rs *.java)
EOF
}

MODEL="${MODEL:-claude-opus-4-5}"
EFFORT="${EFFORT:-max}"
FILE_PATTERNS="${FILE_PATTERNS:-*.c *.h *.py *.js *.ts *.go *.rs *.java}"
DRY_RUN=false
PROJECT_DIR=""

while [[ $# -gt 0 ]]; do
	case "$1" in
		--dry-run)
			DRY_RUN=true
			shift
			;;
		-h | --help)
			usage
			exit 0
			;;
		-*)
			echo "Unknown option: $1"
			exit 1
			;;
		*)
			PROJECT_DIR="$1"
			shift
			;;
	esac
done

PROJECT_DIR="${PROJECT_DIR:-$(pwd)}"
REPORT_ROOT="$PROJECT_DIR/reports"
VALIDATED_DIR="$REPORT_ROOT/validated"

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }

mkdir -p "$VALIDATED_DIR"

# -----------------------------------------------------------------------------
# Gather project context
# -----------------------------------------------------------------------------
log "Scanning project: $PROJECT_DIR"

# Get file list (no glob expansion)
set -f
patterns=($FILE_PATTERNS)
set +f

find_args=()
first=true
for pattern in "${patterns[@]}"; do
	if [[ $first == true ]]; then
		first=false
	else
		find_args+=("-o")
	fi
	find_args+=("-name" "$pattern")
done

FILES=$(find "$PROJECT_DIR" -type d -name '.*' -prune -o \
	-type f \( "${find_args[@]}" \) -print 2>/dev/null | \
	sed "s|^$PROJECT_DIR/||" | sort)

FILE_COUNT=$(echo "$FILES" | wc -l)
log "Found $FILE_COUNT files"

# Build project snapshot (files + content)
PROJECT_SNAPSHOT=""
total_lines=0
max_lines=5000  # Cap to avoid overwhelming context

while IFS= read -r file; do
	[[ -z "$file" ]] && continue
	filepath="$PROJECT_DIR/$file"
	[[ ! -f "$filepath" ]] && continue

	file_lines=$(wc -l < "$filepath")

	if [[ $((total_lines + file_lines)) -gt $max_lines ]]; then
		# Include file name but truncate content
		PROJECT_SNAPSHOT+="
=== $file (truncated, $file_lines lines) ===
$(head -50 "$filepath")
... (truncated)
"
	else
		PROJECT_SNAPSHOT+="
=== $file ===
$(cat "$filepath")
"
		total_lines=$((total_lines + file_lines))
	fi
done <<< "$FILES"

log "Project snapshot: ~$total_lines lines of code"

# Get existing findings
VALIDATED_SUMMARY=""
if compgen -G "$VALIDATED_DIR/*.md" > /dev/null 2>&1; then
	for f in "$VALIDATED_DIR"/*.md; do
		VALIDATED_SUMMARY+="
=== $(basename "$f") ===
$(head -40 "$f")
"
	done
fi

# -----------------------------------------------------------------------------
# Analysis prompt
# -----------------------------------------------------------------------------
ANALYSIS_PROMPT="You are performing a comprehensive security audit of an entire codebase.

## Project Files
$PROJECT_SNAPSHOT

## Existing Validated Findings (avoid duplicates)
${VALIDATED_SUMMARY:-"(None yet)"}

## Your Task

Analyze this ENTIRE codebase for security vulnerabilities. Look for:

**Injection & Input Handling:**
- SQL, Command, LDAP, XPath injection
- Path traversal, file inclusion
- XSS, SSRF, XXE

**Authentication & Access:**
- Authentication bypasses
- Broken access control
- Session management issues
- Hardcoded credentials

**Sandbox/Container Escape:**
- Container breakout (cgroups, namespaces, capabilities)
- seccomp/AppArmor bypass
- /proc, /sys abuse
- Mount escapes, volume traversal
- Unix socket exposure (docker.sock)
- Runtime vulnerabilities (runc, crun, podman)

**Privilege Escalation:**
- SUID/capability abuse
- Kernel interface issues
- Privilege boundary violations

**Memory Safety (for C/C++/Rust):**
- Buffer overflow, use-after-free
- Integer overflow, type confusion
- Race conditions

**Lateral Movement:**
- Credential exposure in env/files
- Token/key leakage
- Network pivoting opportunities

**Crypto Issues:**
- Weak RNG, hardcoded secrets
- Broken crypto implementations

## Output Format

For EACH vulnerability found, write:

---

# [Vulnerability Title]

## Severity: Critical/High/Medium/Low

## CWE: CWE-XXX

## Location
File(s) and line numbers

## Description
What the vulnerability is and why it's dangerous.

## Proof of Concept
Concrete exploitation steps.

## Impact
What an attacker gains.

## Remediation
How to fix it.

---

If no vulnerabilities found, explain what you checked and why the code appears secure.

Be thorough but precise. Only report REAL vulnerabilities, not theoretical concerns."

# -----------------------------------------------------------------------------
# Validation prompt
# -----------------------------------------------------------------------------
run_validation()
{
	local report="$1"

	local VALIDATION_PROMPT="You are a strict security validator. Review this report and validate each finding.

## Report to Validate
$report

## Existing Findings (reject duplicates)
${VALIDATED_SUMMARY:-"(None)"}

## For EACH finding, verify:
1. Is it a REAL vulnerability (not theoretical)?
2. Is the location specific (file + line)?
3. Is exploitation concrete and realistic?
4. Is it NOT a duplicate of existing findings?

## Output
Return a JSON array of validated findings:

[
  {
    \"title\": \"Finding title\",
    \"severity\": \"Critical/High/Medium/Low\",
    \"valid\": true/false,
    \"reasoning\": \"why valid or invalid\"
  }
]

Be STRICT. Reject vague, theoretical, or duplicate findings."

	if [[ $DRY_RUN == "true" ]]; then
		echo '[]'
		return
	fi

	clampdown claude -- \
		--dangerously-skip-permissions \
		--model "$MODEL" \
		--effort "$EFFORT" \
		--print \
		--output-format text \
		-p "$VALIDATION_PROMPT" 2>&1
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
run_id=$(date -u +%Y%m%dT%H%M%SZ)-$$
run_dir="$REPORT_ROOT/runs/$run_id"
mkdir -p "$run_dir"

log "Run: $run_id"
log "Model: $MODEL (effort: $EFFORT)"

# Step 1: Full project analysis
log "Step 1: Analyzing entire project..."

if [[ $DRY_RUN == "true" ]]; then
	log "[DRY-RUN] Would analyze $FILE_COUNT files"
	echo "$ANALYSIS_PROMPT" > "$run_dir/analysis-prompt.txt"
	echo "(dry run)" > "$run_dir/report.md"
else
	clampdown claude -- \
		--dangerously-skip-permissions \
		--model "$MODEL" \
		--effort "$EFFORT" \
		--print \
		--output-format text \
		-p "$ANALYSIS_PROMPT" > "$run_dir/report.md" 2>&1
fi

log "Step 1 complete: $run_dir/report.md"

# Step 2: Validate findings
log "Step 2: Validating findings..."
validation_result=$(run_validation "$(cat "$run_dir/report.md")")
echo "$validation_result" > "$run_dir/validation.json"

# Step 3: Save validated report
report_content=$(cat "$run_dir/report.md")
if echo "$report_content" | grep -q "^# "; then
	# Has findings, save it
	ts=$(date -u +%Y%m%dT%H%M%SZ)
	cp "$run_dir/report.md" "$VALIDATED_DIR/${ts}-project-audit.md"
	log "Report saved: $VALIDATED_DIR/${ts}-project-audit.md"
else
	log "No findings in report"
fi

log "=== Audit Complete ==="
log "Report: $run_dir/report.md"
log "Validation: $run_dir/validation.json"
