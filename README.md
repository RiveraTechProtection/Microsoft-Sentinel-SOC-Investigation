# Simulated Brute-Force Authentication Investigation | Microsoft Sentinel & Defender

**Project type:** Controlled SOC investigation / KQL detection prototype  
**Date:** November 20, 2026  
**Tools:** Microsoft Defender Advanced Hunting, Microsoft Sentinel (workspace configuration), Kusto Query Language (KQL)  
**Author:** RiveraTechProtection

## Executive summary

This portfolio exercise investigates a **synthetic authentication sequence** representing a potential password-guessing attempt against an `admin` account. Seven authentication records were defined with KQL `datatable()`, and a query correlated failed and successful login outcomes by account and source IP. The positive test returned one match; a modified negative test returned none. These results validate the query against the two designed scenarios, **not** its production detection accuracy.

> **Simulation disclosure:** No real account was compromised, no live authentication logs were ingested or analyzed, and no Microsoft Sentinel incident or production detection rule was created. The Microsoft Sentinel workspace was provisioned separately; the queries were executed in Microsoft Defender Advanced Hunting against inline synthetic records.

## Investigation question

Can KQL identify five failed authentication attempts followed by a successful login from the same source IP within a five-minute interval in a controlled dataset?

## Environment and evidence

- Microsoft Sentinel workspace: `LAW-Sentinel-SOC-Lab` (Azure for Students, North Central US), visible in the Azure Sentinel resource list.
- Query execution: Microsoft Defender Advanced Hunting, using inline `datatable()` records.
- Source IPs `203.0.113.50` and `192.0.2.10` are reserved documentation addresses, not attributed threat infrastructure.

| Evidence | Description |
|---|---|
| [Positive detection](screenshots/positive-detection.png) | Five failed attempts, one success, one matching `admin` result |
| [Negative validation](screenshots/negative-test.png) | Modified data with four failures returns zero matches |
| [Authentication timeline](screenshots/authentication-timeline.png) | Six chronological `admin` events |
| [Sentinel workspace](screenshots/sentinel-workspace.png) | Azure resource listing for the Sentinel workspace |
| [Advanced Hunting interface](screenshots/advanced-hunting.png) | Query history and Defender interface |

## Detection logic

See [authentication-detection.kql](authentication-detection.kql). The query:

1. Declares seven synthetic authentication events with `datatable()`.
2. Groups records by `Account` and `SourceIP`.
3. Calculates failure and success counts and relevant event times using `countif()`, `minif()`, and `maxif()`.
4. Requires at least five failures, at least one success, and the first success to occur after the last failure.
5. Requires the elapsed time from first failure to first success to be no more than five minutes.

### Positive test

| Field | Observed value |
|---|---|
| Account | `admin` |
| Source IP | `203.0.113.50` |
| Failed attempts | 5 |
| Successful logins | 1 |
| First failure | 10:00 (synthetic timestamp) |
| Last failure | 10:04 |
| First success | 10:05 |
| Time difference | 5 minutes |
| Matches | 1 |

### Negative test

The 10:04 failed event was changed to `Success`, yielding four failures and two successes for `admin`. The unchanged threshold rejected this case, returning **zero results**. See [negative-validation.kql](negative-validation.kql).

## Findings and analyst assessment

**Finding 1 — Suspicious authentication pattern in simulated data.** Five consecutive failures from a single source IP were followed by a successful login to the same account. This pattern is consistent with password guessing, but is not proof of malicious activity or compromise.

**Finding 2 — Threshold behavior validated for two designed cases.** The query returned one match for the positive scenario and none for the modified negative scenario. Additional testing is required to assess false positives, false negatives, and edge cases.

**Finding 3 — No real-world attribution or impact established.** The account, source IPs, and timestamps are synthetic. No user identity verification, MFA assessment, endpoint investigation, or post-authentication activity was performed.

## Recommended response in a real environment

If this pattern appeared in production telemetry, a SOC analyst should validate the account and source IP, check sign-in and MFA details, review geolocation/device context, inspect activity after the successful login, correlate related alerts, and escalate or contain according to the organization's incident response playbook and authorization procedures.

## Limitations and next steps

- This query summarizes all records per account/IP in the input dataset, rather than implementing a sliding/rolling time window.
- The `FirstSuccess > LastFailure` condition is intentionally restrictive and can miss sequences with interleaved successes or later failures.
- `datetime_diff()` calculates elapsed time between the first failure and first success; it does not enforce a production-grade event sequence across a stream.
- No production alerting, real log ingestion, or response automation was implemented.
- Future improvements: adapt to a real authentication table and schema, use bounded event windows, test varied sequences and benign login patterns, and tune alert thresholds before deployment.

## Formal investigation report

[Download the SOC Investigation Findings Report (PDF)](SOC_Investigation_Findings_Report.pdf)

## Skills demonstrated

KQL query construction and debugging · authentication log analysis · event sequencing · threshold-based detection · positive/negative validation · evidence collection · SOC-style findings documentation.
