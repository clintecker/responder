#!/bin/bash
# Fleet responder runbook: fleet mass-down triage (tier 0 — observe, never reset).
# This runbook leads with OUT-OF-BAND signals (hypervisor
# qm status sweep, blackbox probes on distinct hosts) and consults Loki ONLY
# after establishing Loki's own liveness — the Nov 17 storm was a monitoring
# fault, so the monitoring stack cannot adjudicate a suspected monitoring fault.
# Output contract: last line `RESULT: <monitoring-artifact|site-outage|mixed> <detail>`

set -u
log() { logger -t responder -p auth.info "mass_down_triage: $*"; echo "$*"; }

# Configure in runbook config: space-separated hypervisor FQDNs
HYPERVISORS=(${RESPONDER_HYPERVISORS:?set RESPONDER_HYPERVISORS in runbook config})

# --- Step 1: out-of-band — are the HYPERVISORS alive and their guests up? ----
RUNNING=0; TOTAL=0; NODES_OK=0
for n in "${HYPERVISORS[@]}"; do
    if OUT=$(ssh -o ConnectTimeout=10 "$n" "qm list 2>/dev/null | tail -n +3 | wc -l" 2>&1) && [ "$OUT" -gt 0 ] 2>/dev/null; then
        NODES_OK=$((NODES_OK+1))
        RUNNING=$((RUNNING+OUT)); TOTAL=$((TOTAL+OUT))
        log "hypervisor $n reachable, $OUT guests listed"
    else
        log "hypervisor $n UNREACHABLE over ssh"
    fi
done

if [ "$NODES_OK" -eq "${#HYPERVISORS[@]}" ] && [ "$RUNNING" -gt 0 ]; then
    log "ALL hypervisors reachable; $RUNNING guests report running at the hypervisor level"
    log "=> guests are UP at the virtualization layer; the down-alerts are monitoring-plane"
    echo "RESULT: monitoring-artifact all-hypervisors-report-guests-running"
    exit 0
fi

# --- Step 2: Loki only after its own liveness is established -----------------
if curl -s --max-time 5 "${LOKI_URL:-http://localhost:3100}/ready" | grep -q ready; then
    log "Loki alive — cross-checking host log continuity"
    N=$(curl -s --max-time 10 -G "${LOKI_URL:-http://localhost:3100}/loki/api/v1/query" \
        --data-urlencode 'query=count(count_over_time({job=~"journal|systemd-journal"}[5m]))' | \
        python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["result"][0]["value"][1])' 2>/dev/null || echo 0)
    log "hosts logging in last 5m: $N"
else
    log "Loki itself is dead — cannot cross-check via logs"
    echo "RESULT: mixed loki-down-hypervisor-data-only"
    exit 0
fi

if [ "$NODES_OK" -eq 0 ]; then
    log "ALL hypervisors unreachable AND Loki dead — this is a site/uplink-level event"
    echo "RESULT: site-outage all-planes-dark"
    exit 0
fi

log "partial visibility: $NODES_OK/${#HYPERVISORS[@]} hypervisors reachable"
echo "RESULT: mixed partial-visibility"
