# Sentinel — AI-Assisted Linux Vulnerability Assessment Agent

**Portfolio project · Python 3.10+ · v0.2.0 · Detection-first**

Sentinel is a local Linux CLI that combines natural-language scan planning with a constrained scanner orchestrator. You can type a request such as “Scan 192.168.149.129 for exposed services and safe vulnerability indicators.” An AI provider converts the request to a small JSON plan; the local program validates the requested host against your configured private scope and maps the model's choices to a fixed scanner allowlist.

> **Status:** functional MVP, not a finished enterprise scanner. Three scanner integrations are wired in: Nmap, Nuclei (optional), and testssl.sh (optional). The project does not currently integrate 200+ tools, does not exploit vulnerabilities, and does not promise that a scan will detect every issue.

## Features

- Natural-language scan planning through OpenAI, Anthropic Claude, or Google Gemini APIs.
- AI output is restricted to a target decision and `nmap`, `nuclei`, `tls` check labels. **The model cannot provide or execute shell commands.**
- Local target validation: target must be contained inside a configured RFC1918 private IPv4 scope.
- Dry-run by default; execution requires both `authorized: true` in the local scope file and explicit CLI confirmation flags.
- Nmap service/version discovery; optional conservative Nuclei templates; optional TLS configuration checks.
- Timestamped output folders with scanner logs, Nmap XML, derived web/TLS target lists, JSON summary, and the AI plan.
- Python standard-library-only controller. Scanner binaries remain separate and follow their upstream licenses.

## Architecture

```text
Natural-language request
          |
          v
OpenAI / Claude / Gemini (plan only; JSON response)
          |
          v
Local validator (RFC1918 + configured scope + host budget)
          |
          v
Fixed adapter allowlist (Nmap / Nuclei / testssl.sh)
          |
          v
Logs + inventory + JSON report for analyst validation
```

The AI API receives the prompt you submit. The controller does not send scanner results to the AI in this MVP. Do not include passwords, tokens, customer data, or other secrets in prompts. A plan from an LLM is treated as untrusted input and revalidated locally.

## Requirements

- Linux (Ubuntu/Debian recommended) and Python 3.10+
- Nmap installed; Nuclei and `testssl.sh` are optional
- An API key from exactly one selected AI provider for natural-language mode
- Written authorization for every target you scan

Install the baseline scanner on Ubuntu:

```bash
sudo apt update
sudo apt install -y nmap python3
```

Install optional tools from their official documentation and verify package provenance. Do not pipe unreviewed install scripts directly to a root shell.

## 1. Download and configure

```bash
git clone https://github.com/bilal7533-sec/linux-hardening.git
cd linux-hardening
cp .env.example .env
nano .env
```

Choose one provider in `.env`, then set its API key and a model name valid for your account. The `.env` file is ignored by Git. To load it into your current shell without an extra Python dependency:

```bash
set -a
source .env
set +a
```

Provider variables:

| Provider | Key variable | Optional model variable |
|---|---|---|
| OpenAI | `OPENAI_API_KEY` | `OPENAI_MODEL` |
| Claude | `ANTHROPIC_API_KEY` | `ANTHROPIC_MODEL` |
| Gemini | `GEMINI_API_KEY` | `GEMINI_MODEL` |

Defaults are provided in `.env.example`; change the model variable if that model is not enabled for your API account. API usage may be billed by the provider.

## 2. Configure authorized scope

```bash
nano config/scope.json
```

Example for a private lab host. The default configuration deliberately uses `authorized: false` and must be reviewed before any scan can run:

```json
{
  "authorized": false,
  "scope": ["192.168.149.129/32"],
  "rate_limit": 5,
  "max_hosts": 64,
  "tools": {
    "nmap": true,
    "nuclei": false,
    "testssl": false
  }
}
```

Use your actual host or subnet. Sentinel rejects public/special ranges, IPv6, broad scopes larger than the configured host budget, and AI-selected targets outside this file. Set `authorized` to `true` only after written permission is in place. Optional scanners must be installed and explicitly enabled in this file.

## 3. Natural-language dry run

```bash
python3 sentinel_agent.py \
  --request "Scan 192.168.149.129 for open services and safe vulnerability indicators"
```

This sends your prompt to the selected AI provider and prints the interpreted scan plan and exact local commands. It does **not** scan the target unless `--execute` is present. If you omit a target or the request is ambiguous, the agent should ask you to specify it. `CONFIG_SCOPE` is used only when the request explicitly refers to the configured scope.

## 4. Run an authorized scan

After verifying that the target belongs to the configured scope and you have permission:

```bash
python3 sentinel_agent.py \
  --request "Scan 192.168.149.129 for open services and safe vulnerability indicators" \
  --execute \
  --confirm-authorized
```

The controller blocks execution unless both CLI switches are present and `authorized` is `true` in `config/scope.json`. No exploit validation, password guessing, brute-force, denial-of-service, persistence, or stealth/evasion is performed.

Without AI, the configured scope can be previewed or scanned using the same controls:

```bash
python3 sentinel_agent.py
python3 sentinel_agent.py --execute --confirm-authorized
```

## 5. Review output

Results are placed in `reports/scan-YYYYMMDD-HHMMSS/`:

- `request_plan.json` — selected provider/model, interpreted plan, and validated scope (AI mode)
- `nmap.xml` / `nmap.log` — discovered hosts, services, and scanner evidence
- `web_targets.txt` / `tls_targets.txt` — endpoints derived from Nmap results
- `nuclei.jsonl` / `nuclei.log` — optional template matches
- `testssl.log` — optional TLS assessment log
- `summary.json` — run metadata and asset inventory

Treat scanner output as evidence for analyst triage, not automatic proof of exploitability. Validate findings and remediation before closing an issue.

## Tests

```bash
python3 -m unittest discover -s tests -v
python3 sentinel_agent.py --version
```

Tests do not contact an AI provider and do not scan a network.

## Known limitations

- MVP supports RFC1918 IPv4 only. IPv6, authenticated SSH posture collection, cloud account assessment, containers, source/dependency analysis, SIEM integration, HTML/SARIF reporting, finding deduplication, and authenticated scanner APIs are not wired in yet.
- Nmap uses the top 1,000 TCP ports and light service detection; this is not exhaustive UDP coverage.
- Nuclei is off by default and restricted to selected low-impact tags. Review templates and scope before enabling.
- `testssl.sh` is off by default and checks endpoints inferred from Nmap. Virtual-host/SNI discovery may require manual configuration.
- An AI plan may misinterpret a prompt; local scope validation and operator confirmation remain mandatory.
- 200+ tool support is a roadmap, not a current capability. Each integration needs a tested adapter, maintained parser, license review, rate/time limits, and safety policy before it is marked implemented.

## Roadmap

1. Read-only authenticated Linux posture checks over SSH.
2. Greenbone/OpenVAS integration through its supported API.
3. A normalized finding schema with CVE/CWE, severity, evidence, confidence, remediation, and validation status.
4. HTML/JSON/SARIF reports and deduplication.
5. A versioned adapter registry with timeout/rate caps and parser fixtures for each new tool.
6. Container, cloud, code/dependency, IaC, secrets, SBOM, and compliance adapters after individual verification.

## License

MIT; see [LICENSE](LICENSE). Third-party scanners and AI services retain their own licensing and usage terms.
