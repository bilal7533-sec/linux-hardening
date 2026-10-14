# Integration roadmap (planned, not currently wired in)

These are candidate integrations, not a claim that they are already installed or integrated. Each needs a maintained adapter, output parser and safe execution policy.

| Domain | Candidate integrations |
|---|---|
| Network/ports | Nmap, arp-scan, fping, netcat (restricted), RustScan (rate-capped) |
| Vulnerability management | Greenbone/OpenVAS API, Nessus API (licensed), Qualys API (licensed), Rapid7 InsightVM API (licensed) |
| Web/API | OWASP ZAP API, Nikto (controlled), WhatWeb, testssl.sh, SSLyze, httpx, katana (scope-capped) |
| Template-driven detection | Nuclei (curated tags/templates, reviewed updates) |
| Linux hardening | Lynis, OpenSCAP/SCAP Security Guide, osquery, auditd rules checks |
| Container/image | Trivy, Grype, Syft, Dockle, kube-bench, kube-hunter (controlled environment only) |
| Code/dependencies | Semgrep, Bandit, Ruff, pip-audit, npm audit, osv-scanner, Gitleaks |
| IaC/cloud | Checkov, KICS, Prowler, ScoutSuite |
| Secrets/SBOM | Gitleaks, TruffleHog (authorized repositories only), Syft, CycloneDX tooling |
| Reporting/normalization | DefectDojo API, SARIF, CycloneDX, SPDX, JSON, HTML/PDF renderer |

Some products are commercial, renamed, merged, deprecated, or impose licensing/API restrictions. Before adding them, verify project maintenance, version compatibility, license, source provenance and output format. 200+ tool coverage should be incremental and evidence-based; invoking arbitrary binaries with generic arguments is unsafe and produces low-quality results.
