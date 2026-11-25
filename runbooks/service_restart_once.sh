#!/bin/bash
# Fleet responder runbook: single failed service — restart ONCE (tier 1).
# The wrapper's 2-attempt cap backs this up mechanically (council MUST #3).
# If the service is `down` again after the restart, RESULT: escalate.
# Usage: service_restart_once.sh <unit-name> [host-fqdn defaults to local]

set -u
UNIT="${1:?usage: service_restart_once.sh <unit> [host]}"
HOST="${2:-localhost}"
log() { logger -t responder -p auth.info "service_restart_once: $*"; echo "$*"; }

RUN() {
    if [ "$HOST" = "localhost" ]; then sudo -n "$@"; else ssh -o ConnectTimeout=10 "$HOST" "sudo -n $*"; fi
}

# Precondition: unit actually failed (not just inactive-by-design)
STATE=$(RUN systemctl is-active "$UNIT" 2>&1)
if [ "$STATE" != "failed" ] && [ "$STATE" != "inactive" ]; then
    log "unit $UNIT is '$STATE' — not failed, no action"
    echo "RESULT: noaction state=$STATE"
    exit 0
fi
log "unit $UNIT is $STATE — restarting once"

# Action: the ONE restart
if ! RUN systemctl restart "$UNIT"; then
    log "ERROR: restart command failed"
    echo "RESULT: escalate restart-command-failed"
    exit 1
fi

sleep 5
STATE2=$(RUN systemctl is-active "$UNIT" 2>&1)
if [ "$STATE2" = "active" ]; then
    log "recovery verified: $UNIT active after restart"
    echo "RESULT: ok restarted-active"
    exit 0
fi
log "restart did not produce active state ($STATE2) — escalating (attempt cap backs this)"
echo "RESULT: escalate still-$STATE2-after-restart"
exit 1
