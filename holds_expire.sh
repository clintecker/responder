#!/bin/bash
# Weekly expiry for responder apt-mark holds: persistent mutations expire.
# Un-holds anything stamped by kernel_panic_hold.sh more than 7 days ago and
# reports holds with no stamp (pre-timer holds, held by hand) for visibility.
# Installed fleet-wide by setup_responder_identity.yml; runs via
# responder-holds-expire.timer.
set -u
STAMP_DIR=/var/lib/responder/holds
MAX_AGE=$((7*24*3600))   # 7 days

log() { logger -t responder-holds -p auth.info "holds-expire: $*"; }

mkdir -p "$STAMP_DIR"
now=$(date +%s)
changed=0

for f in "$STAMP_DIR"/*; do
    [ -f "$f" ] || continue
    pkg=$(basename "$f")
    stamped=$(head -c 30 "$f" 2>/dev/null || true)
    ts=$(date -u -d "$stamped" +%s 2>/dev/null) || { log "unreadable stamp: $pkg"; continue; }
    if [ $((now - ts)) -gt $MAX_AGE ]; then
        if apt-mark unhold "$pkg" >/dev/null 2>&1; then
            log "EXPIRED: un-held $pkg (held since $stamped)"
            rm -f "$f"
            changed=$((changed + 1))
        else
            log "ERROR: unhold failed for $pkg — left held, stamp kept"
        fi
    fi
done

# Holds with no stamp: not ours (manual holds) — report only, never touch.
unstamped=$(comm -23 <(apt-mark showhold | sort) <(find "$STAMP_DIR" -type f -printf '%f\n' 2>/dev/null | sort))
if [ -n "$unstamped" ]; then
    log "REPORT: holds with no expiry stamp (manual?): $(echo "$unstamped" | tr '\n' ' ')"
fi

if [ "$changed" -gt 0 ]; then
    log "SUMMARY: $changed hold(s) expired this run"
fi
exit 0
