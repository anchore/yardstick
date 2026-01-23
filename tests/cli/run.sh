#!/usr/bin/env bash
#
# Smoke test for yardstick CLI commands.
#
# This test verifies that CLI commands execute successfully with real tool
# invocations. It does NOT assert on specific output content - those checks
# are handled by the integration tests in tests/integration/cli/.
#
# This test guards against:
# - Tool installation/invocation failures
# - Subprocess communication issues
# - Environment/path problems
#

set -euo pipefail

ERROR="\033[1;31m"
SUCCESS="\033[1;32m"
TITLE="\033[1;35m"
RESET="\033[0m"

i=0

function run() {
    echo -e "${TITLE}$i| Running $@${RESET}"
    if "$@"; then
        echo -e "${SUCCESS}Success${RESET}"
    else
        echo -e "${ERROR}Exited with $?${RESET}"
        exit 1
    fi
    i=$((i + 1))
}

# Result commands
run uv run yardstick result clear
run uv run yardstick result capture -r test
run uv run yardstick result list -r test

# Compare command (get grype result IDs and compare them)
GRYPE_IDS=$(uv run yardstick result list -r test --ids -t grype)
run uv run yardstick result compare $GRYPE_IDS

# Label commands
RESULT_ID=$(uv run yardstick result list -r test --ids -t grype | head -1)
run uv run yardstick label apply "$RESULT_ID"

ID_TO_REMOVE=$(uv run yardstick label add -i foo -c CVE-1234-ASDF -p test-package -v 1.2.3 -n "testing" --label TP)
run uv run yardstick label remove "$ID_TO_REMOVE"

echo -e "\n${SUCCESS}PASS${RESET}"
