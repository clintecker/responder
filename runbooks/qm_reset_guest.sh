#!/bin/bash
# Fleet responder runbook: qm reset of a verified-hung guest (tier 1).
# Usage: qm_reset_guest.sh <fqdn-or-vmid> <hypervisor-fqdn>
#
# Preconditions are machine-checkable and annotated for signal INDEPENDENCE
# (agent-death and console-silence correlate — both die early in a wedge —
# so the hypervisor-side status check carries decisive weight).
# Every step is logged to the responder audit namespace via logger.
# Output contract: last line is `RESULT: <ok|escalate|noaction> <detail>`.

set -u
log() { logger -t responder -p auth.info "qm_reset_guest: $*"; echo "$*"; }

# Accepts: qm_reset_guest.sh <vmid> <node-fqdn>   OR   <vmid@node> (single arg,
# the form the classifier's brief carries — instance "201@hv-01").
if [[ "$1" == *"@"* ]]; then
    VMID="${1%%@*}"; NODE="${1##*@}"
else
    VMID="$1"; NODE="$2"
fi
# GUEST: resolvable address of the guest OS (arg 3). NEVER the bare VMID —
# ssh treats "201" as 0.0.201 (found live 2026-11-23 by the drill responder,
# twice documented in its artifacts). Without a guest address the SSH probes
# are skipped; the agent check alone carries the wedge evidence.
GUEST="$3"
if ! [[ "$VMID" =~ ^[0-9]+$ ]]; then
    log "ERROR: VMID must be numeric (got: $VMID)"
    echo "RESULT: escalate vmid-not-numeric"
    exit 1
fi
if [ -z "$NODE" ]; then
    log "ERROR: hypervisor node required"
    echo "RESULT: escalate node-missing"
    exit 1
fi
# Normalize node to FQDN if short name given
case "$NODE" in *.* ) ;; *) NODE="$NODE.${RESPONDER_DOMAIN:-example.internal}" ;; esac

# --- Precondition 1 (Hypervisor-side, independent, decisive) ---------------
ST=$(ssh -o ConnectTimeout=10 "$NODE" "sudo -n qm status $VMID" 2>&1)
if ! echo "$ST" | grep -q "status: running"; then
    log "precondition-1 FAILED: qm status says: $ST"
    echo "RESULT: noaction not-running ($ST)"
    exit 0
fi
log "precondition-1 ok: $NODE qm status $VMID = running"

# --- Precondition 2 (Guest-side: qemu-guest-agent) --------------------------
AGENT=0
for i in 1 2; do
    if ssh -o ConnectTimeout=10 "$NODE" "qm agent $VMID ping" >/dev/null 2>&1; then
        AGENT=1; break
    fi
    sleep 5
done
if [ "$AGENT" = "1" ]; then
    log "precondition-2 FAILED: guest agent answers — guest is NOT hung; refusing reset"
    echo "RESULT: escalate agent-alive-not-hung"
    exit 0
fi
log "precondition-2 ok: qemu-guest-agent unreachable (2 tries)"

# --- Precondition 3 (Network-side: SSH to the guest) ------------------------
if [ -z "$GUEST" ]; then
    log "precondition-3 SKIPPED: no guest address provided (agent check is the sole network-side evidence)"
elif ssh -o ConnectTimeout=10 -o BatchMode=yes "$GUEST" true >/dev/null 2>&1; then
    log "precondition-3 FAILED: guest SSH reachable — not hung"
    echo "RESULT: escalate ssh-alive-not-hung"
    exit 1
else
    log "precondition-3 ok: guest SSH unreachable"
fi
# --- Correlated-signal caveat: agent+ssh checks correlate -------------------
log "NOTE: agent-dead + ssh-dead are correlated (both die early in a wedge); the hypervisor-side running state is the independent anchor. If the guest were merely slow, reset is recoverable either way (a running guest losing power-safe state is the accepted cost, documented in the runbook review)."

# --- Action: reset -----------------------------------------------------------
log "all preconditions met — resetting VM $VMID on $NODE"
if ssh -o ConnectTimeout=10 "$NODE" "sudo -n qm reset $VMID"; then
    log "reset command sent"
else
    log "ERROR: qm reset failed"
    echo "RESULT: escalate reset-command-failed"
    exit 1
fi

# --- Recovery verification (against the original signal: SSH) ----------------
UP=0
if [ -z "$GUEST" ]; then
    log "recovery check SKIPPED: no guest address — recovery is unverifiable by this runbook"
else
for i in $(seq 1 30); do
    sleep 10
    if ssh -o ConnectTimeout=10 -o BatchMode=yes "$GUEST" true >/dev/null 2>&1; then
        UP=1; break
    fi
done
fi
if [ "$UP" = "1" ]; then
    log "recovery verified: $GUEST answers SSH after reset"
    echo "RESULT: ok guest-recovered"
    exit 0
fi
if [ -z "$GUEST" ]; then
    log "reset fired but recovery is unverifiable without a guest address"
    echo "RESULT: escalate recovery-unverifiable-no-guest-address"
    exit 1
fi
log "recovery NOT verified within 5 min"
echo "RESULT: escalate no-recovery-after-reset"
exit 1
