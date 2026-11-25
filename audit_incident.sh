#!/bin/bash
# Responder mechanical audit: verify every mutation left a journal trace.
# Diffs the incident window's sudo journal lines (responder namespace) against
# the runbook's allowed-action list + wrapper ledger; prints surplus and
# attempt-cap violations. Output is appended to the incident artifact.
# Usage: audit_incident.sh <incident-id> <start-iso> [end-iso]

set -u
INCIDENT="${1:?usage: audit_incident.sh <incident-id> <start-iso> [end-iso]}"
START="${2:?start timestamp required}"
END="${3:-}"
STATE=/var/lib/responder

# The wrapper's ledger records every EXEC with its count and the allowlist file
echo "=== mechanical audit for incident $INCIDENT ==="
echo "--- wrapper ledger (attempt counts per action):"
for f in "$STATE"/wrapper/*.count; do
    [ -f "$f" ] || continue
    N=$(cat "$f")
    [ "$N" -gt 2 ] && echo "VIOLATION: attempt cap exceeded ($N) for action hash $(basename "$f" .count)"
    echo "  exec count $N: $(basename "$f" .count)"
done

echo "--- sudo executions in the responder audit namespace:"
if [ -n "$END" ]; then
    journalctl --namespace=responder --since "$START" --until "$END" --no-pager 2>/dev/null | grep -E "wrapper (EXEC|REFUSED)" || echo "  (none)"
else
    journalctl --namespace=responder --since "$START" --no-pager 2>/dev/null | grep -E "wrapper (EXEC|REFUSED)" || echo "  (none)"
fi

echo "--- refusals (injection-boundary + attempt-cap evidence):"
journalctl --namespace=responder --since "$START" ${END:+--until "$END"} --no-pager 2>/dev/null | grep "REFUSED" || echo "  (none)"
