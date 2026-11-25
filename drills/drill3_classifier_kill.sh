#!/bin/bash
# Chaos drill 3: kill the classifier, fire a critical, prove the EMAIL
# fallback still routes (council MUST #4: email is the permanent fallback).
# This drill touches the LIVE alerting pipeline; the test alert uses a
# fingerprintless name so nothing spawns even if the classifier were up.
set -u
PASS=0; FAIL=0
ok()  { echo "  PASS: $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $*"; FAIL=$((FAIL+1)); }
step(){ echo "── $*"; }
# AM host + responder container coordinates
AM="${RESPONDER_AM_HOST:?set RESPONDER_AM_HOST}"

step "1. stop the classifier on the responder LXC"
ssh -o ConnectTimeout=10 "$RESPONDER_DRILL_NODE" "pct exec $RESPONDER_DRILL_LXC -- systemctl stop responder-classifier" && ok "classifier stopped" || bad "stop failed"
STATE=$(ssh -o ConnectTimeout=10 "$RESPONDER_DRILL_NODE" "pct exec $RESPONDER_DRILL_LXC -- systemctl is-active responder-classifier")
[ "$STATE" = "inactive" ] && ok "confirmed inactive" || bad "still $STATE"

step "2. fire a critical with no classifier running"
ssh -o ConnectTimeout=10 "$AM" "amtool alert add test_alert_name=DrillThree severity=critical instance=drill3 --alertmanager.url=http://localhost:9093/alertmanager" >/dev/null 2>&1 && ok "alert fired into AM" || bad "amtool failed"

step "3. wait for routing + capture the mail relay evidence"
sleep 25
EVID=$(ssh -o ConnectTimeout=10 "$AM" "journalctl --since '-5min' --no-pager 2>/dev/null | grep -E 'postfix.*relay' | tail -4" || true)
echo "$EVID" | grep -qi "relay" && ok "mail relay attempted (mail relay in mail.log)" || { echo "$EVID" | head -3; bad "no mail relay evidence found"; }

step "4. restore the classifier"
ssh -o ConnectTimeout=10 "$RESPONDER_DRILL_NODE" "pct exec $RESPONDER_DRILL_LXC -- systemctl start responder-classifier"
sleep 3
ST=$(ssh -o ConnectTimeout=10 "$RESPONDER_DRILL_NODE" "pct exec $RESPONDER_DRILL_LXC -- systemctl is-active responder-classifier")
[ "$ST" = "active" ] && ok "classifier restored" || bad "classifier $ST after restore"

step "5. resolve the drill alert"
ssh -o ConnectTimeout=10 "$AM" "curl -s -X POST -H 'Content-Type: application/json' -d '[{\"labels\":{\"test_alert_name\":\"DrillThree\",\"severity\":\"critical\",\"instance\":\"drill3\"},\"endsAt\":\"2020-01-01T00:00:00.000Z\"}]' http://localhost:9093/alertmanager/api/v2/alerts -o /dev/null -w '%{http_code}'" | grep -q 200 && ok "drill alert resolved" || bad "resolve failed"

echo
echo "═══ DRILL 3 RESULT: PASS=$PASS FAIL=$FAIL ═══"
[ "$FAIL" -eq 0 ]
