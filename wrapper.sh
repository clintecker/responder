#!/bin/bash
# Fleet responder wrapper — mechanical enforcement of tier-1 actions.
# Council MUST #3: guards live in the harness, not the prompt. This wrapper:
#   1. accepts ONLY commands whose exact line appears in the ACTIVE runbook's
#      action list (passed via env from the spawn),
#   2. counts invocations per action (state dir), refuses the third attempt,
#   3. logs everything to the responder audit namespace.
# The agent invokes: wrapper.sh <allowed-action-line>
# Any argument not literally matching an allowed line = refused.

set -u
STATE=/var/lib/responder/wrapper
mkdir -p "$STATE"
LINE="$*"
ALLOWED_FILE="${RESPONDER_ALLOWED_ACTIONS:?wrapper requires RESPONDER_ALLOWED_ACTIONS env}"

if ! grep -qxF "$LINE" "$ALLOWED_FILE"; then
    logger -t responder -p auth.warning "wrapper REFUSED (not in runbook allowlist): $LINE"
    echo "REFUSED: command not in the active runbook's action list" >&2
    exit 2
fi

# attempt cap: 2 per exact line
KEY=$(echo "$LINE" | md5sum | cut -d' ' -f1)
N=$(($(cat "$STATE/$KEY.count" 2>/dev/null || echo 0) + 1))
if [ "$N" -gt 2 ]; then
    logger -t responder -p auth.warning "wrapper REFUSED (attempt cap $N): $LINE"
    echo "REFUSED: attempt cap exceeded for this action" >&2
    exit 3
fi
echo "$N" > "$STATE/$KEY.count"

logger -t responder -p auth.info "wrapper EXEC #$N: $LINE"
# Execute: the allowed line is a full command string — run it under bash -c
# (the allowlist is the security boundary, not the wrapper's parsing)
eval "$LINE"
rc=$?
logger -t responder -p auth.info "wrapper EXEC #$N rc=$rc: $LINE"
exit $rc
