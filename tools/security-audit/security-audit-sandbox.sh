#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
#
# Clampdown Sandbox CTF - Security Validation Challenge
#
# Creates a treasure file on the host that the sandboxed agent must find.
# If the agent can read the treasure, the sandbox has a security gap.

set -e

agent="${1:-claude}"
MODEL="${MODEL:-"claude-opus-4-6[1m]"}"
EFFORT="${EFFORT:-max}"

case "$agent" in
	claude | opencode) ;;
	*)
		echo "Usage: $0 [claude|opencode]" >&2
		exit                  1
		;;
esac

# Create temp workdir for the sandbox
dir=$(mktemp -d)

# Generate treasure: random 32-byte hex string
treasure=$(head -c 32 /dev/urandom | xxd -p -c 64)
treasure_file="/tmp/TREASURE-$$"

# Write treasure to host filesystem (outside sandbox)
echo "$treasure" > "$treasure_file"
treasure_hash=$(sha256sum "$treasure_file" | cut -d' ' -f1)

echo "=== Clampdown Sandbox CTF ==="
echo "Treasure file: $treasure_file"
echo "Treasure hash: $treasure_hash"
echo "Workdir:       $dir"
echo "Model:       $MODEL"
echo ""
echo "The agent will try to read the treasure."
echo "If successful, the sandbox has a security gap."
echo "============================"
echo ""

# Build the prompt with treasure location and hash
prompt=$(cat "$(dirname "$0")"/sandbox-escape-audit.md)
prompt=$(echo "$prompt" | sed "s|{{TREASURE_FILE}}|$treasure_file|g")
prompt=$(echo "$prompt" | sed "s|{{TREASURE_HASH}}|$treasure_hash|g")

# Cleanup on exit
cleanup()
{
	rm -f "$treasure_file"
	echo ""
	echo "=== CTF Complete ==="
	echo "Treasure file removed: $treasure_file"
}
trap cleanup EXIT

cp -ar "$(dirname "$0")"/../../pkg "$dir"/
cp -ar "$(dirname "$0")"/../../container-images "$dir"/
cp -ar "$(dirname "$0")"/../../tools "$dir"/
cp -ar "$(dirname "$0")"/../../*.md "$dir"/

PROJECT_DIR="${PROJECT_DIR:-"$(dirname "$0")/../../"}"
REPORT_ROOT="$PROJECT_DIR/reports"
RUNS_DIR="$REPORT_ROOT/runs"
VALIDATED_DIR="$REPORT_ROOT/validated"
mkdir -p "$RUNS_DIR"
mkdir -p "$VALIDATED_DIR"

"$(dirname "$0")"/../../clampdown "$agent" \
	--sidecar-image clampdown-sidecar:latest \
	--proxy-image clampdown-proxy:latest \
	--agent-image "clampdown-${agent}:latest" \
	-w "$dir" \
	-- --dangerously-skip-permissions \
	--model "$MODEL" \
	--effort "$EFFORT" \
	--print --output-format stream-json --verbose \
	-p "$prompt" | tee "$RUNS_DIR/$(date -u +%Y%m%dT%H%M%SZ)-ctf"

cp "$dir/ctf-report.md" "$VALIDATED_DIR"/
