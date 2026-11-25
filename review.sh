#!/bin/bash
# Periodic review ritual. Surfaces: every incident + its
# disposition, wrapper-ledger attempt counts, and current apt-mark holds
# with expiry stamps on the hosts that have any.
set -u
NODE="${RESPONDER_NODE:?set RESPONDER_NODE (responder host)}"
LXC="${RESPONDER_LXC:?set RESPONDER_LXC (responder container id)}"
RESPONDER_DOMAIN="${RESPONDER_DOMAIN:?set RESPONDER_DOMAIN}"
FLEET="${FLEET_HOSTS:?set FLEET_HOSTS (space-separated host short names)}"

echo "═══ RESPONDER REVIEW — $(date -u +%FT%TZ) ═══"
echo
echo "── Incidents on the responder LXC:"
ssh -o ConnectTimeout=10 "$NODE" "pct exec $LXC -- bash -c '
  for d in /var/lib/responder/incidents/*; do
    [ -d \"\$d\" ] || continue
    echo \"  \$(basename \$d):\"
    grep -m1 -E \"RESULT|Disposition\" \"\$d/artifact.md\" 2>/dev/null | sed \"s/^/    /\"
  done
  echo
  echo \"── Wrapper ledger (exec/refuse counts):\"
  wc -l /var/lib/responder/ledger/* 2>/dev/null | sed \"s/^/    /\"
  echo
  echo \"── Classifier heartbeat:\"
  stat -c \"    heartbeat: %y\" /var/lib/responder/heartbeat 2>/dev/null
'" 2>/dev/null || echo "  responder host unreachable"

echo
echo "── apt-mark holds across the fleet (stamped = responder-set, expires +7d):"
for h in $FLEET; do
  holds=$(ssh -o ConnectTimeout=8 -o BatchMode=yes "root@$h.$RESPONDER_DOMAIN" "apt-mark showhold 2>/dev/null" 2>/dev/null)
  if [ -n "$holds" ]; then
    echo "  $h:"
    echo "$holds" | sed 's/^/    /'
    ssh -o ConnectTimeout=8 -o BatchMode=yes "root@$h.$RESPONDER_DOMAIN" \
      "for f in /var/lib/responder/holds/*; do [ -f \"\$f\" ] && echo \"    stamp: \$(basename \$f) = \$(cat \$f)\"; done" 2>/dev/null
  fi
done
echo
echo "── Done. Open the artifacts you have not read; adopt-or-reject each."
