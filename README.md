# responder

An alert-driven remediation agent for small/medium fleets. A static
classifier receives Alertmanager criticals, matches them against a
fingerprint table, and spawns a fresh low-privilege agent session that
executes a deterministic runbook — with machine-checkable preconditions,
mechanical guardrails, and a written artifact for every incident.

Born on a ~30-host Proxmox + Ansible fleet where it handled real incidents
(a verified-hung VM reset, a false-positive HostDown it correctly declined
to act on) after surviving three chaos drills. Sanitized of all
site-specific values; every fleet-specific coordinate is an environment
variable or a table you fill in.

```
classifier.py        webhook + fingerprint router + spawn + locks + dashboard
fingerprints.yml     static alert fingerprints → runbook / escalate
runbooks/            tier-1 scripts; last line: RESULT: <ok|escalate|noaction>
drills/              chaos drills; no runbook arms without a passing drill
wrapper.sh           mechanical allowlist + attempt-cap executor
artifact-template.md the per-incident artifact shape
holds_expire.sh      expiry sweep for persistent mutations
review.sh            the periodic human review ritual
deploy/              the identity + sudoers Ansible playbook
examples/            sample payloads and config
docs/DESIGN.md       the architecture and non-negotiables
```

## How an incident flows

1. Alertmanager delivers a critical batch to `POST /alert`.
2. The classifier dedupes (1h window, resolution-aware 6h re-fire cooldown),
   acquires a per-target lock, matches the fingerprint table.
3. Known fingerprint with a tier-1 runbook → fresh agent session (unprivileged
   user, 30-minute budget) with a brief and the raw payload.
4. The agent reads the brief, executes the runbook, writes `artifact.md`.
5. Unknown/noisy fingerprints → push notification only. The human decides.
6. Everything lands in the audit journal and the artifact.

## Status

Production pattern, POC-grade packaging. The code runs as-is on a Debian-ish
host with Proxmox (`qm`/`pct`) and systemd; adapting it to other platforms
means writing new runbooks and swapping the tool calls, not changing the
architecture.
