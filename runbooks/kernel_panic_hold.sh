#!/bin/bash
# Fleet responder runbook: kernel panic signature near unattended-upgrade (tier 1).
# Response (from the Nov 18 web incident, postmortem in the fleet docs):
# hold the suspect kernel package so the nightly can't re-panic the host,
# verify dpkg state, PROPOSE the reboot (reboots stay human-scheduled).
# Success criterion (council): diagnosis complete + human notified — NOT
# "incident resolved"; the reboot itself is the owner's.
#
# Usage: kernel_panic_hold.sh <host-fqdn> [package-glob, default linux-image-*]
# Output contract: last line `RESULT: <ok|noaction|escalate> <detail>`

set -u
HOST="${1:?usage: kernel_panic_hold.sh <host> [package-glob]}"
PKG="${2:-linux-image-*}"
log() { logger -t responder -p auth.info "kernel_panic_hold: $*"; echo "$*"; }
R() { ssh -o ConnectTimeout=10 "$HOST" "sudo -n $*"; }

# --- Evidence: the panic signature in the CURRENT boot's predecessor ---------
PANIC=$(ssh -o ConnectTimeout=10 "$HOST" "sudo -n journalctl -b -1 --no-pager 2>/dev/null | grep -c 'kernel: BUG:'" 2>/dev/null || echo 0)
APTTIME=$(ssh -o ConnectTimeout=10 "$HOST" "sudo -n grep -l 'unattended' /var/log/apt/history.log >/dev/null 2>&1 && echo yes || echo no" 2>/dev/null)
log "evidence: prior-boot kernel BUG lines=$PANIC apt-unattended-history=$APTTIME"

if [ "${PANIC:-0}" -eq 0 ]; then
    log "no panic signature in the prior boot — not the kernel-panic class"
    echo "RESULT: noaction no-panic-signature"
    exit 0
fi

# --- Find the kernel package dpkg was configuring when it died ---------------
SUSPECT=$(ssh -o ConnectTimeout=10 "$HOST" "sudo -n grep -B2 'End-Date' /var/log/apt/history.log | grep -oE 'linux-image-[0-9.]+-[0-9]+-amd64' | tail -1" 2>/dev/null)
if [ -z "$SUSPECT" ]; then
    SUSPECT=$(ssh -o ConnectTimeout=10 "$HOST" "sudo -n dpkg --audit 2>/dev/null | head -1 | awk '{print \$1}'" 2>/dev/null)
fi
if [ -z "$SUSPECT" ]; then
    log "could not identify the suspect package — escalating"
    echo "RESULT: escalate suspect-package-unidentified"
    exit 1
fi
log "suspect package: $SUSPECT"

# --- Action: hold it (persistent mutation — recorded for the weekly expiry) --
HELD=$(R "apt-mark showhold" 2>/dev/null | grep -c "$SUSPECT" || true)
if [ "${HELD:-0}" -gt 0 ]; then
    log "$SUSPECT already held"
    echo "RESULT: noaction already-held"
    exit 0
fi
if R "apt-mark hold $SUSPECT"; then
    # Stamp the hold with its date: the weekly expiry timer reads these to
    # un-hold anything older than 7 days (persistent mutations expire).
    mkdir -p /var/lib/responder/holds
    echo "$(date -u +%FT%TZ)" > "/var/lib/responder/holds/$SUSPECT"
    chmod 644 "/var/lib/responder/holds/$SUSPECT"
    log "MUTATION: apt-mark hold $SUSPECT expires +7d (weekly un-hold timer files the expiry)"
    echo "RESULT: ok held-$SUSPECT-reboot-proposed"
    log "PROPOSE: reboot $HOST to complete recovery — human-scheduled by design"
    exit 0
fi
log "ERROR: apt-mark hold failed"
echo "RESULT: escalate hold-failed"
exit 1
