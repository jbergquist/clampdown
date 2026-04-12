#!/bin/sh

dir=$(mktemp -d)

"$(dirname "$0")"/../../clampdown claude -w "$dir" -- --dangerously-skip-permissions --model claude-opus-4-5 --effort max --print -p "$(cat "$(dirname "$0")"/sandbox-escape-audit.md)"
