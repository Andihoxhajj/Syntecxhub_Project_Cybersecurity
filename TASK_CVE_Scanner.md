# Task: Vulnerability / CVE Scanner

## Overview

Build a lightweight scanner that checks services and versions against known CVEs (Common Vulnerabilities and Exposures) or signatures.

---

## Requirements

### 1. Service & Version Detection
- **Banner grabbing** — Connect to open ports and capture service banners (e.g., SSH, HTTP, FTP headers)
- **Service detection** — Identify running services and their versions from banners and responses

### 2. CVE Lookup
- Query CVE databases/APIs (e.g., NVD, CVE.org, Vulners) with detected product/version info
- Match services and versions against known vulnerabilities

### 3. Reporting
- Produce a **report** with:
  - Possible CVE matches
  - Severity notes (CVSS scores, risk levels)
  - Clear, actionable output (e.g., JSON, HTML, or text)

### 4. Educational Component
- **Responsible disclosure** — Document how to report vulnerabilities to vendors and coordinators (e.g., CERT, vendor security contacts)
- **Triage basics** — Explain how to prioritize findings (severity, exploitability, asset criticality)

---

## Suggested Deliverables

| Item | Description |
|------|-------------|
| Scanner script/tool | Lightweight implementation (e.g., Python) |
| CVE lookup integration | API client for at least one CVE database |
| Report output | Structured report with matches and severity |
| Documentation | Short guide on responsible disclosure and triage |

---

## Notes

- Keep the scanner **lightweight** — suitable for learning and small-scale assessments
- Ensure compliance with target systems’ terms of service and authorization before scanning
- Use only on systems you own or have explicit permission to test
