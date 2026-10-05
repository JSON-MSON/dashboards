# CSF 2.0 Artifacts

The coverage table in this repository's README shows representative artifacts for each function. This file names all twelve, as of August 2026.

## What counts as an artifact

A distinct piece of work from `packet-analysis-lab`, `siem-home-lab`, `linux-audit-lab`, `iam-ad-lab` or `incident-reports` that produces the outcome a CSF 2.0 function describes. Not a plan, not a recommendation, not the same work counted twice under different names.

`log-ioc-parser` and `dashboards` contribute none: the parser is analytical tooling rather than a standing detection capability, and `dashboards` reports on artifacts rather than being one. `log-ioc-parser` is counted in [`VERIFICATION_STEPS.md`](VERIFICATION_STEPS.md), which measures something different.

---

## Govern — 0

None. Govern covers organizational risk strategy, policy, and oversight — 31 of CSF 2.0's 106 subcategories, and the function furthest from what hands-on lab work produces. The closest candidate, the monitoring decision under Identify, is a risk response for one system rather than strategy, policy, or oversight.

The portfolio's formal governance work is a separate deliverable, `governance-risk-lab`: the NIST RMF applied to this lab, covering security categorization, control selection and tailoring, a partial assessment of nine controls, and a plan of action and milestones. Remediation status is tracked there, not here.

## Identify — 3

1. **Full 65,535-port scan of actual attack surface.** Covered three listening services outside Nmap's default scan range, which the host's own socket list had shown were there. — [`packet-analysis-lab`](https://github.com/JSON-MSON/packet-analysis-lab)
2. **Endpoint software inventory.** Installed-software data collected from the domain-joined Windows client via the remote monitoring and management (RMM) platform. — [`iam-ad-lab`](https://github.com/JSON-MSON/iam-ad-lab)
3. **Decision not to extend SIEM monitoring to the Windows client.** Extending monitoring would have required a network route between the isolated attack-simulation segment and the real network; the decision was to accept reduced visibility rather than create that path. That is a risk response (ID.RA-06, "Risk responses are chosen, prioritized, planned, tracked, and communicated"), not a technical control. — `iam-ad-lab`

## Protect — 2

1. **Domain password policy.** Complexity enabled, 12-character minimum, 5-password history, confirmed active on the running domain. — `iam-ad-lab`
2. **Default-deny host firewall.** Open ports reduced from five to two, measured from a separate machine. — `packet-analysis-lab`

The Helpdesk-IT password-reset delegation is not counted: as configured, the entry sits on the organizational unit without inheritance and does not reach the user accounts (see `iam-ad-lab`).

## Detect — 4

1. **Wazuh rule 100010.** SSH brute force (T1110, ATT&CK v19.2), confirmed against live attack traffic. — [`siem-home-lab`](https://github.com/JSON-MSON/siem-home-lab)
2. **Wazuh rule 100011.** Repeated failed `sudo`/PAM authentication (T1548, ATT&CK v19.2), confirmed against live attempts. — `siem-home-lab`
3. **FIM rule 550 coverage on `auth.log`.** File integrity monitoring that detected deliberate log truncation. — [`incident-reports`](https://github.com/JSON-MSON/incident-reports)
4. **Scheduled filesystem drift detection.** A cron-scheduled audit comparing each run against the previous snapshot, confirmed to flag both additions and removals. — [`linux-audit-lab`](https://github.com/JSON-MSON/linux-audit-lab)

The MITRE ATT&CK coverage layer and the custom dashboard panels are deliberately **not** counted: both report on detection rather than performing it.

## Respond — 2

1. **incident-01.** Unauthorized local account creation and privilege escalation: timeline, indicators, triage, escalation decision, containment. — `incident-reports`
2. **incident-02.** Authentication log tampering: separate host, separate technique, separate evidence set, plus the detection-engineering work required to make it detectable. — `incident-reports`

Containment actions are part of the report they belong to and are not counted separately.

## Recover — 1

1. **Samba DC backup and restore.** A file-level backup taken, a controller failure simulated, and the restored domain's user list compared against a snapshot taken beforehand. The snapshot is committed, so the comparison can be re-run against the live domain. No incident occurred; the test exercises RC.RP-05 ("The integrity of restored assets is verified, systems and services are restored, and normal operating status is confirmed"). — `iam-ad-lab`

Recover assumes restoration of affected systems and services. Neither documented incident required restoration, so this exercise is the only recovery work.

---

## Totals

| Function | Artifacts |
|---|---|
| Govern | 0 |
| Identify | 3 |
| Protect | 2 |
| Detect | 4 |
| Respond | 2 |
| Recover | 1 |
| **Total** | **12** |
