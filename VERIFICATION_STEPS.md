# Verification Steps

The counts in this repository's Findings Dashboard are listed here step by step, so they can be checked rather than taken on trust. They cover the hands-on labs as of August 2026.

## The test

A step counts when it confirms a claim that **already exists**, against a source **independent of the one that made the claim**.

Three parts, all required:

1. **A claim exists first.** Something reported success, or a tool produced output. Work done before any claim exists is preparation, not verification.
2. **A second source.** A different tool, a different machine, a different layer, or raw data instead of a tool's summary of it.
3. **Genuine independence.** The second source must not share the first source's blind spot.

This draws on the assessment methods in [NIST SP 800-53A Rev 5](https://doi.org/10.6028/NIST.SP.800-53Ar5) — Test (exercising an assessment object under specified conditions to compare actual with expected behavior) and Examine (checking, inspecting or reviewing an assessment object to obtain evidence). The independence requirement in *The test* above is this metric's own, not part of 800-53A's method definitions.

**What this metric does not claim.** A formal assessment under SP 800-53A Rev 5 also weighs *assessor independence* — an assessor free from conflicts of interest, at a level the authorizing official sets. A single-operator lab cannot provide that. What is measured here is independence of *evidence source*, not of person.

---

## packet-analysis-lab — 3

1. **Full-range scan re-run after hardening.** `nmap -sV -T4 -p-` run before and after enabling the firewall, identical command both times, from the attacking machine rather than the target. Five open ports reduced to two. Both outputs committed as `nmap_before_firewall_full.txt` and `nmap_after_firewall_full.txt`.
2. **Firewall ruleset read back.** `ufw status verbose` queried the stored ruleset separately from the scan, confirming default-deny and the two intended allow rules — a different source from the scan's observed reachability.
3. **Raw capture searched directly.** `strings` on the packet capture instead of relying on the protocol dissector's parsed summary, confirming the submitted credentials appear in plaintext on the wire.

**Excluded — `ss -tulnp` listening-socket inventory.** This ran *before* any firewall rule existed and determined which ports to allow. It revealed three services outside Nmap's default scan range, which is what made the before/after comparison meaningful, but no claim existed for it to test. Preparation, not verification.

## siem-home-lab — 5

1. **Rule 100010 validated in isolation.** `wazuh-logtest` exercised the rule's matching logic against a known sample line, with no network traffic involved.
2. **Rule 100010 confirmed against live traffic.** A real brute-force run produced alerts from the custom rule, testing the same rule through the alert pipeline rather than the rule engine alone.
3. **Test input checked against real log data.** Rule 100011 had been built against a base rule ID derived from a hand-written test line. Comparing that line to an actual `auth.log` entry showed the real format matches a different base rule — a check on the validity of another verification step, not on the rule itself.
4. **Rule 100011 validated in isolation.** `wazuh-logtest` re-run against the corrected base rule.
5. **Rule 100011 confirmed against live activity.** Real failed `sudo` attempts produced the alert through the full pipeline.

Steps 1 and 2, and steps 4 and 5, are each counted separately because they test different claims through different mechanisms. SP 800-53A Rev 5 distinguishes testing that assumes no knowledge of internal structure from testing that assumes knowledge of implementation detail; `wazuh-logtest` inspects the rule's internal matching, while a live attack does not.

**Excluded — dashboard "Missing = 1" reconciliation** (a single reading of a panel) and **`agent_control -l`** (a single observation after setup, with no prior claim to test).

## linux-audit-lab — 4

1. **Before/after audit diff.** The audit script re-run after remediation, its output diffed against the pre-remediation run, rather than trusting `chmod`'s success. Both files committed.
2. **Drift detection confirmed for an addition.** A test file created; the next run flagged it. Committed in `audit_history/`.
3. **Drift detection confirmed for a removal.** The same file removed; the next run flagged the removal. Detecting additions does not demonstrate detecting removals.
4. **Unattended path tested with cron's exact redirect syntax.** The script run manually with the same `>> audit_cron.log 2>&1` redirection the scheduled job uses, confirming output format before relying on the schedule.

## log-ioc-parser — 5

1. **Measurement instability found, and the log frozen.** Repeated validation counts against the live log kept rising, which showed that a live log plus a validation command writing into that same log cannot produce a stable comparison.
2. **JSON output parsed by an independent parser.** `json.tool` errors on malformed input rather than accepting it, confirming structural validity beyond visual plausibility.
3. **Table and JSON summary counts cross-checked.** Confirms the two output modes are not diverging code paths.
4. **`Received:` chain traced against the SPF-authorized address.** SPF's own pass is one source; the routing chain is another, confirming the message arrived from where it claimed.
5. **DKIM alignment checked against the DMARC verdict.** Explains *why* DMARC passed despite the SPF domain mismatch, rather than reading the verdict alone.

Step 5 is the weakest of the five on source independence — every field it reads comes from the message's own headers (the receiving server's authentication results and the sender's DKIM signature), with no outside source. It is counted because it reasons from a verdict to the underlying data that produced it, which is more than a single reading.

**Excluded — parser output compared against `grep -c`.** Both used the same pattern against the same file, so both counted three logged `sudo` command lines whose text contained the search string. The counts matched exactly, which looked like confirmation. Two sources sharing a blind spot are one source. See that project's README for the corrected figure.

## iam-ad-lab — 7

1. **Delegation entry read back off the object.** The raw access-control entry retrieved from the OU rather than trusting `dsacl set`'s success message. Committed as `delegation_ace.txt`. It confirms the entry was written to the OU, not the access it was meant to grant (see that project's key finding).
2. **Password policy read back.** `passwordsettings show` confirming complexity, minimum length, and history actually stored.
3. **Lockout confirmed at the directory level.** A non-zero `lockoutTime` on the target account, confirming the domain acted rather than inferring it from failed logins.
4. **SIEM alerts confirming the same attack independently.** The detection layer recorded the attack from `auth.log` on a different host, with no dependency on the directory's lockout state.
5. **Pre-failure and restored state compared.** The domain's user list diffed against a snapshot taken before the simulated failure. The snapshot is committed, so this comparison can be re-run against the live domain at any time.
6. **Endpoint enrollment confirmed two ways.** Locally via `Get-Service`, and in the management console — agent-side and server-side.
7. **Both local accounts confirmed in one listing.** Accounts created through two different interfaces, confirmed together in a single user list.

**Excluded — `Test-NetConnection` after clearing a persistent route** (verified lab network hygiene, not a security control this portfolio claims) and **the Kerberos ticket check** (no prior claim to test; establishing that the domain works, not verifying an assertion about it).

---

## Totals

| Project | Steps |
|---|---|
| packet-analysis-lab | 3 |
| siem-home-lab | 5 |
| linux-audit-lab | 4 |
| log-ioc-parser | 5 |
| iam-ad-lab | 7 |
| **Total** | **24** |

Six steps are excluded by name above. The exclusions matter as much as the inclusions: a metric with no stated boundary can be adjusted after the fact to produce whatever number is wanted.
