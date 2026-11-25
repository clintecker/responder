# Incident: {{ incident_id }}

**Fingerprint:** {{ fingerprint }} · **Host:** {{ host }} · **Tier:** {{ tier }}
**Started:** {{ started }} · **Status:** {{ status }}

## What fired

{{ alerts_summary }}

## Independent verification

| Check | Source | Result |
|---|---|---|
| {{ check1_name }} | {{ check1_source }} | {{ check1_result }} |

(verification commands with RAW output — never paraphrased)

## Actions taken

| # | Action | Timestamp | Journal ref | Result |
|---|---|---|---|---|
| 1 | {{ action }} | {{ ts }} | journalctl -t responder | {{ result }} |

<details>
<summary>Verbatim machine record (sudo journal, responder namespace)</summary>

```
{{ journal_excerpts }}
```
</details>

## Recovery verification

{{ recovery_raw_output }}

## Explicitly NOT touched

- {{ n1 }}

## Open questions for the operator

- {{ q1 }}

## Mechanical audit

```
{{ audit_output }}
```
