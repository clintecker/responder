#!/bin/bash
# Fleet responder runbook: EndpointDown remediation — diagnose-then-act.
# Design: docs/plans/2026-11-24-endpoint-down-remediation.md (oracle-revised).
#
# Decision tree (G0..G5). Every tier-1 action is gated by its own evidence
# precondition. This pilot handles ONE endpoint; the mapping table below is
# where new endpoints are added (each with its own drill before arming).
#
# Usage (from the incident brief):
#   endpoint_down_diagnose.sh <probe-url>
# Output contract: last line is `RESULT: <ok|escalate|noaction> <detail>`.
set -u
URL="${1:?usage: endpoint_down_diagnose.sh <probe-url>}"
log() { logger -t responder -p auth.info "endpoint_down: $*"; echo "$*"; }
die() { log "RESULT: escalate $*"; exit 1; }

# DRILL_FAST=1 shortens the wait loops for drill runs only (10x60s -> 3x20s
# for the G0 gate, 10x30s -> 3x10s for recovery checks). The drill sets it;
# the classifier never does.
if [ "${DRILL_FAST:-0}" = "1" ]; then
    G0_TRIES=3; G0_SLEEP=20; REC_TRIES=3; REC_SLEEP=10
else
    G0_TRIES=10; G0_SLEEP=55; REC_TRIES=10; REC_SLEEP=30
fi

# --- Target mapping table (M5: URL is a KEY, never interpolated into
# --- action lines; every action line below is fully static) ---------------
# url|canonical-host|vmid|hypervisor-fqdn|guest-ssh-user|guest-ssh-addr|restart-units
MAPPING='
# Replace these example rows with your own mapping; each row needs its own
# drill pass before its fingerprint is armed (M5 rule: URL is a table KEY).
https://app.example.com|app|101|hv-01.example.internal|deploy|app.example.internal|caddy.service
# DRILL row: a scratch target never probed by real alerts; drills only.
http://198.51.100.10:8080|drill-target|201|hv-01.example.internal|deploy|198.51.100.10|drill-app.service
'
ROW=$(echo "$MAPPING" | grep -F "$URL" | head -1)
[ -n "$ROW" ] || die "url-not-in-table ($URL)"
CANON=$(echo "$ROW" | cut -d'|' -f2)
VMID=$(echo "$ROW" | cut -d'|' -f3)
NODE=$(echo "$ROW" | cut -d'|' -f4)
GUSER=$(echo "$ROW" | cut -d'|' -f5)
GADDR=$(echo "$ROW" | cut -d'|' -f6)
UNITS=$(echo "$ROW" | cut -d'|' -f7)
URL_HOST=$(echo "$URL" | sed 's|https\?://||; s|/.*||')
log "target: url=$URL canon=$CANON vmid=$VMID node=$NODE guest=$GADDR"

# --- Attempt cap (M4: inside the runbook, the wrapper ledger is not wired) --
MARKER="/var/lib/responder/endpoint_attempts"
NOWDAY=$(date -u +%F)
LASTDAY=""; N=0
[ -f "$MARKER" ] && read -r LASTDAY N < "$MARKER" 2>/dev/null
[ "$LASTDAY" = "$NOWDAY" ] || N=0
if [ "${N:-0}" -ge 3 ]; then
    die "attempt-cap-reached ($N today) — human involvement required"
fi

# --- G2/M2 preflight: hypervisor reachable + not silenced -------------------
SSH_OPTS="-o ConnectTimeout=10 -o BatchMode=yes -o StrictHostKeyChecking=accept-new"
if ! ssh $SSH_OPTS "$NODE" true >/dev/null 2>&1; then
    die "hypervisor-unreachable ($NODE) — transport failure is not guest state"
fi
# A stopped hypervisor can't tell us about the VM; refuse to act.
# (M2: AM silences are honored upstream by the classifier's dedupe; the
# runbook additionally refuses if the VM has a current maintenance note.)
TASKLOG=$(ssh $SSH_OPTS "$NODE" "sudo -n qm task last 2>/dev/null" 2>&1)
# M1: refuse to fight a recent human stop. If the newest task on this VM is
# a STOP/SHUTDOWN that finished < 2h ago, this may be maintenance.
if echo "$TASKLOG" | grep -qE "VM $VMID.*(Stop|Shutdown|Stop)"; then
    log "NOTE: recent stop/shutdown task found on VM $VMID — possible maintenance"
    log "RESULT: escalate recent-stop-task — confirm maintenance window first"
    exit 1
fi

# --- G0: 10-minute persistence gate, IN-SESSION bounded wait ---------------
# The alert fires at 2m; the responder waits out transient blips here so a
# failed gate does not waste the spawn (AM re-notifies at 4h otherwise).
log "G0: persistence gate — probing every 60s, waiting up to 10m"
for i in $(seq 1 10); do
    # From the probe vantage: blackbox lives on prometheus; query its metric
    # Direct query: the classifier LXC has LAN access to Prometheus:9090;
    # no ssh hop (the responder key is not on prometheus by design — v1
    # exclusion — and none is needed to read the API).
    P=$(curl -s --data-urlencode "query=probe_success{instance=\"$URL\"}" \
        ${PROM_URL:-http://localhost:9090}/api/v1/query 2>/dev/null \
        | grep -oE '"value":\[[^,]+,"[01]"\]' | grep -oE '"[01]"\]$' | tr -d '"]')
    # ABSENT series = probe infrastructure fault, never "up" (oracle B3)
    if [ -z "$P" ]; then
        log "G0: probe series ABSENT — blackbox/prometheus fault is possible"
        log "RESULT: escalate probe-series-absent — probe infrastructure, not the target"
        exit 1
    fi
    if [ "${P%.*}" = "1" ] || [ "$P" = "1" ]; then
        log "G0: probe RECOVERED on check $i/10 — transient blip, no action"
        echo "RESULT: noaction transient-recovered"
        exit 0
    fi
    sleep $G0_SLEEP
done
log "G0: still down after the persistence window — proceeding"

# --- G1: probe honesty, two INDEPENDENT vantages (oracle B3) ---------------
# Vantage 1: the target's own hypervisor. Vantage 2: a different host on
# a different path (prometheus is NOT independent — it runs the blackbox
# exporter that raised the alert).
V1=$(ssh $SSH_OPTS "$NODE" "curl -s -o /dev/null -w '%{http_code}' --max-time 8 '$URL'" 2>/dev/null)
V2=$(ssh $SSH_OPTS "${VANTAGE_2:?set VANTAGE_2 in the runbook config}" "curl -s -o /dev/null -w '%{http_code}' --max-time 8 '$URL'" 2>/dev/null)
log "G1: vantages — $NODE=$V1 v2=$V2"
if [ "$V1" = "200" ] && [ "$V2" = "200" ]; then
    log "G1: both vantages reach the URL — the PROBE is lying"
    log "RESULT: noaction probe-lying (vantages ok: $NODE=$V1 v2=$V2)"
    exit 0
fi
if [ "$V1" = "200" ] || [ "$V2" = "200" ]; then
    log "G1: SPLIT verdict — network-path issue, not a target fault"
    log "RESULT: escalate network-path-split (v1=$V1 v2=$V2)"
    exit 1
fi
log "G1: both vantages fail — real outage confirmed"

# --- G2: hypervisor-side VM state (B5 handled in preflight) ----------------
ST=$(ssh $SSH_OPTS "$NODE" "sudo -n qm status $VMID" 2>&1)
if echo "$ST" | grep -q "status: stopped"; then
    # ACTION-A: start (evidence: qm status says stopped, transport verified)
    log "G2: VM stopped — starting"
    if ssh $SSH_OPTS "$NODE" "sudo -n qm start $VMID"; then
        log "ACTION-A: qm start sent; waiting for probe recovery (5m)"
        for i in $(seq 1 $REC_TRIES); do
            sleep $REC_SLEEP
            P=$(curl -s --data-urlencode "query=probe_success{instance=\"$URL\"}" \
                ${PROM_URL:-http://localhost:9090}/api/v1/query 2>/dev/null \
                | grep -oE '"value":\[[^,]+,"[01]"\]' | grep -oE '"[01]"\]$' | tr -d '"]')
            [ "$P" = "1" ] && { log "recovery verified at check $i"; echo "RESULT: ok vm-started-recovered"; exit 0; }
        done
        die "started-but-no-recovery (probe still failing after 5m)"
    fi
    die "qm start failed"
fi
if echo "$ST" | grep -q "status: paused"; then
    # A paused VM ignores qm reset (the reset request waits for the vCPU —
    # found in drill 4c). Resume is the correct action and it is instantly
    # verifiable.
    log "G2: VM PAUSED — resuming (a paused VM cannot process a reset)"
    if ssh $SSH_OPTS "$NODE" "sudo -n qm resume $VMID"; then
        sleep 10
        P=$(curl -s --data-urlencode "query=probe_success{instance=\"$URL\"}" \
            ${PROM_URL:-http://localhost:9090}/api/v1/query 2>/dev/null \
            | grep -oE '"value":\[[^,]+,"[01]"\]' | grep -oE '"[01]"\]$' | tr -d '"]')
        if [ "$P" = "1" ]; then
            log "recovery verified post-resume"
            echo "RESULT: ok vm-resumed-recovered"
            exit 0
        fi
        log "resumed but probe still failing — continuing tree"
    fi
    ST=$(ssh $SSH_OPTS "$NODE" "sudo -n qm status $VMID" 2>&1)
fi
echo "$ST" | grep -q "status: running" || die "qm status unparseable: $ST"
log "G2: VM running"

# --- G3: guest liveness — agent ping + serial heartbeat (M3) ----------------
# Three semi-independent signals: qm agent ping, guest SSH, serial heartbeat
# mtime. Correlation caveat applies to agent+ssh (they die together early);
# the serial heartbeat file on the HYPERVISOR is the freshest independent
# anchor (the capture daemon writes it host-side, no guest involvement).
AGENT_DEAD=1
ssh $SSH_OPTS "$NODE" "sudo -n qm agent $VMID ping" >/dev/null 2>&1 && AGENT_DEAD=0
SSHDEAD=1
ssh $SSH_OPTS -o ConnectTimeout=8 "$GUSER@$GADDR" true >/dev/null 2>&1 && SSHDEAD=0
HB_AGE=$(ssh $SSH_OPTS "$NODE" "stat -c %Y /var/log/vm-serial/${VMID}.log 2>/dev/null" 2>/dev/null)
TNOW=$(date +%s)
HB_STALE=unknown
if [ -n "$HB_AGE" ]; then
    D=$((TNOW - HB_AGE))
    if [ "$D" -gt 300 ]; then HB_STALE="stale($((D/60))min)"; else HB_STALE="fresh($((D/60))min)"; fi
fi
log "G3: agent-dead=$AGENT_DEAD ssh-dead=$SSHDEAD serial-heartbeat=$HB_STALE"

if [ "$AGENT_DEAD" = "1" ] && [ "$SSHDEAD" = "1" ]; then
    if [ "$HB_STALE" != "unknown" ] && echo "$HB_STALE" | grep -q stale; then
        log "G3: agent+ssh dead AND serial heartbeat stale — wedge signature confirmed 3 ways"
    else
        log "G3: agent+ssh dead but serial heartbeat fresh — guest is ALIVE and writing; NOT a wedge"
        log "NOTE: this is boot-time (agent/ssh not yet up). Wait once, 3m, then re-check."
        sleep 180
        ssh $SSH_OPTS "$NODE" "sudo -n qm agent $VMID ping" >/dev/null 2>&1 && AGENT_DEAD=0
        ssh $SSH_OPTS -o ConnectTimeout=8 "$GUSER@$GADDR" true >/dev/null 2>&1 && SSHDEAD=0
        if [ "$AGENT_DEAD" = "0" ] || [ "$SSHDEAD" = "0" ]; then
            log "G3: guest came alive during the wait — booting, not wedged; re-running tree"
            echo "RESULT: noaction booting-transient"
            exit 0
        fi
    fi
    # ACTION-B: the drill-proven reset (one attempt — attempt cap enforces)
    log "ACTION-B: verified wedge — qm reset $VMID (one attempt)"
    if ssh $SSH_OPTS "$NODE" "sudo -n qm reset $VMID"; then
        log "reset sent; verifying probe recovery (5m)"
        for i in $(seq 1 $REC_TRIES); do
            sleep $REC_SLEEP
            P=$(curl -s --data-urlencode "query=probe_success{instance=\"$URL\"}" \
                ${PROM_URL:-http://localhost:9090}/api/v1/query 2>/dev/null \
                | grep -oE '"value":\[[^,]+,"[01]"\]' | grep -oE '"[01]"\]$' | tr -d '"]')
            [ "$P" = "1" ] && { log "recovery verified at check $i"; echo "RESULT: ok reset-recovered"; exit 0; }
        done
        die "reset-no-recovery (probe still failing after 5m)"
    fi
    die "qm reset failed"
fi
log "G3: guest alive (agent=$([ $AGENT_DEAD -eq 0 ] && echo yes || echo no) ssh=$([ $SSHDEAD -eq 0 ] && echo yes || echo no))"

# --- G4: app layer — local check must MIRROR the probe (oracle B4) ---------
# Same URL, same scheme, same Host, same TLS: --resolve pins the URL's host
# to loopback so we test the full local stack through the guest's own name.
# --resolve pins the URL's hostname to loopback so the guest tests its own
# full stack under the name the outside world uses. For IP-literal URLs
# (drill probes) there is no name to pin: curl the URL directly.
if echo "$URL_HOST" | grep -qE '^[0-9.]+$'; then
    LOCAL=$(ssh $SSH_OPTS "$GUSER@$GADDR" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 8 '${URL}'" 2>/dev/null)
else
    LOCAL=$(ssh $SSH_OPTS "$GUSER@$GADDR" \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 8 --resolve ${URL_HOST}:443:127.0.0.1 '${URL}'" 2>/dev/null)
fi
log "G4: local check via --resolve: HTTP $LOCAL"
if [ "$LOCAL" = "200" ]; then
    log "G4: local stack answers 200 but the outside world cannot — proxy/tunnel layer"
else
    # ACTION-C: one enumerated restart of the mapped units. The unit names
    # come from the mapping table (static, human-reviewed — M5: never from
    # the alert payload).
    log "G4: app layer not answering correctly ($LOCAL) — one restart attempt"
    R1=""
    for U in ${UNITS//,/ }; do
        R=$(ssh $SSH_OPTS "$GUSER@$GADDR" "sudo -n systemctl restart $U && systemctl is-active $U" 2>&1)
        log "ACTION-C: systemctl restart $U -> $R"
        R1="$R1 $U=$R"
    done
    for i in $(seq 1 $REC_TRIES); do
        sleep $REC_SLEEP
        P=$(curl -s --data-urlencode "query=probe_success{instance=\"$URL\"}" \
            ${PROM_URL:-http://localhost:9090}/api/v1/query 2>/dev/null \
            | grep -oE '"value":\[[^,]+,"[01]"\]' | grep -oE '"[01]"\]$' | tr -d '"]')
        [ "$P" = "1" ] && { log "recovery verified at check $i"; echo "RESULT: ok app-restart-recovered"; exit 0; }
    done
    # one more chance: the tunnel (adopted nice-to-have, still ONE attempt total per unit)
    log "caddy restart did not recover the probe — tunnel layer check"
    R2=$(ssh $SSH_OPTS "$GUSER@$GADDR" "systemctl is-active cloudflared.service" 2>&1)
    log "cloudflared status: $R2"
    if [ "$R2" != "active" ]; then
        ssh $SSH_OPTS "$GUSER@$GADDR" "sudo -n systemctl restart cloudflared.service" >/dev/null 2>&1
        log "ACTION-C: cloudflared restarted (was: $R2)"
        for i in $(seq 1 $REC_TRIES); do
            sleep $REC_SLEEP
            P=$(curl -s --data-urlencode "query=probe_success{instance=\"$URL\"}" \
                ${PROM_URL:-http://localhost:9090}/api/v1/query 2>/dev/null \
                | grep -oE '"value":\[[^,]+,"[01]"\]' | grep -oE '"[01]"\]$' | tr -d '"]')
            [ "$P" = "1" ] && { log "recovery verified"; echo "RESULT: ok tunnel-restart-recovered"; exit 0; }
        done
    fi
    die "restart-no-recovery (caddy+$([ "${R2:-?}" = active ] && echo tunnel || echo local) exhausted)"
fi

# --- G5: proxy/tunnel layer — ONE gated restart then escalate ---------------
# (External-only failure: local stack answers 200. Likeliest cause: a dead
# caddy or tunnel process on a DIFFERENT hop, or an upstream outage.)
log "G5: local OK + external dead — checking the guest's own caddy/cloudflared"
CADDY=$(ssh $SSH_OPTS "$GUSER@$GADDR" "systemctl is-active caddy.service" 2>&1)
log "G5: caddy=$CADDY"
if [ "$CADDY" != "active" ]; then
    ssh $SSH_OPTS "$GUSER@$GADDR" "sudo -n systemctl restart caddy.service" >/dev/null 2>&1
    log "G5: caddy was '$CADDY' — restarted"
    for i in $(seq 1 $REC_TRIES); do
        sleep $REC_SLEEP
        P=$(curl -s --data-urlencode "query=probe_success{instance=\"$URL\"}" \
            ${PROM_URL:-http://localhost:9090}/api/v1/query 2>/dev/null \
            | grep -oE '"value":\[[^,]+,"[01]"\]' | grep -oE '"[01]"\]$' | tr -d '"]')
        [ "$P" = "1" ] && { log "recovery verified"; echo "RESULT: ok caddy-restart-recovered"; exit 0; }
    done
fi
die "external-only-failure unresolved — proxy/upstream needs a human"
