#!/usr/bin/env python3
"""Sentinel Linux Vulnerability Assessment Agent (safe-by-default starter).

This orchestrator runs discovery/configuration checks against explicitly scoped,
authorized private IPv4 networks. It does not exploit findings, brute-force, fuzz,
or attempt persistence.
"""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

APP_NAME = "Sentinel Linux Vulnerability Assessment Agent"
DEFAULT_SCOPE = Path("config/scope.json")
RFC1918_NETWORKS = tuple(ipaddress.ip_network(item) for item in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def load_scope(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"Scope file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Scope file is not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("Scope file root must be a JSON object.")
    scope = data.get("scope")
    if not isinstance(scope, list) or not scope:
        raise ValueError("scope must be a non-empty list of IPv4 addresses/CIDRs.")

    parsed: list[str] = []
    for raw in scope:
        if not isinstance(raw, str):
            raise ValueError(f"Every scope item must be a string, got: {raw!r}")
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid IP/CIDR in scope: {raw!r}") from exc
        if net.version != 4:
            raise ValueError("This starter currently supports IPv4 only.")
        if not any(net.subnet_of(private_net) for private_net in RFC1918_NETWORKS):
            raise ValueError(
                f"Scope target {raw!r} is not within an RFC1918 private IPv4 network. "
                "This starter intentionally blocks public and special-purpose ranges by default."
            )
        # Avoid accidentally broad scopes such as /8; intentionally scoped networks only.
        if net.prefixlen < 16:
            raise ValueError(f"Scope {raw!r} is too broad (prefix must be /16 or narrower, e.g. /24).")
        parsed.append(str(net))

    data["scope"] = sorted(set(parsed))
    # Hard cap scan size to reduce accidental large-scope scans. The operator may
    # select a smaller limit, but cannot raise it above 4,096 IPv4 addresses here.
    try:
        max_hosts = int(data.get("max_hosts", 1024))
    except (TypeError, ValueError) as exc:
        raise ValueError("max_hosts must be an integer between 1 and 4096.") from exc
    if max_hosts < 1 or max_hosts > 4096:
        raise ValueError("max_hosts must be an integer between 1 and 4096.")
    total_addresses = sum(ipaddress.ip_network(item).num_addresses for item in data["scope"])
    if total_addresses > max_hosts:
        raise ValueError(
            f"Configured scope contains {total_addresses} addresses, exceeding max_hosts={max_hosts}. "
            "Narrow the CIDRs or deliberately set a reviewed limit (maximum 4096 in this starter)."
        )
    data["max_hosts"] = max_hosts
    data["rate_limit"] = max(1, min(int(data.get("rate_limit", 5)), 20))
    tools = data.get("tools", {})
    if not isinstance(tools, dict):
        raise ValueError("tools must be a JSON object.")
    data["tools"] = {
        "nmap": bool(tools.get("nmap", True)),
        "nuclei": bool(tools.get("nuclei", False)),
        "testssl": bool(tools.get("testssl", False)),
    }
    return data


def resolve_requested_target(target: str, configured_scope: dict[str, Any]) -> str:
    """Return a canonical target only if it is wholly contained in configured scope."""
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError as exc:
        raise ValueError(f"AI-selected target {target!r} is not a valid IPv4 address/CIDR.") from exc
    if network.version != 4 or not any(network.subnet_of(private_net) for private_net in RFC1918_NETWORKS):
        raise ValueError("AI-selected target is outside the allowed RFC1918 private IPv4 range.")
    allowed = [ipaddress.ip_network(item, strict=False) for item in configured_scope["scope"]]
    if not any(network.subnet_of(parent) for parent in allowed):
        raise ValueError(f"AI-selected target {network} is not contained in configured scope: {configured_scope['scope']}.")
    if network.num_addresses > configured_scope["max_hosts"]:
        raise ValueError(f"AI-selected target contains {network.num_addresses} addresses, above max_hosts={configured_scope['max_hosts']}.")
    return str(network)


def require_authorization(scope: dict[str, Any], args: argparse.Namespace) -> None:
    if not scope.get("authorized", False):
        raise PermissionError("Scope config has authorized=false. Review ownership/permission, then set it to true.")
    if not args.confirm_authorized:
        raise PermissionError("Execution requires --confirm-authorized after verifying written permission.")
    if not args.execute:
        raise PermissionError("No scans were run. Add --execute after reviewing the dry-run plan.")


def command_available(name: str) -> str | None:
    return shutil.which(name)


def discover_tool_paths() -> dict[str, str | None]:
    return {
        "nmap": command_available("nmap"),
        "nuclei": command_available("nuclei"),
        "testssl.sh": command_available("testssl.sh") or command_available("testssl"),
    }


def planned_commands(scope: dict[str, Any], output_dir: Path) -> list[list[str]]:
    commands: list[list[str]] = []
    targets = scope["scope"]
    if scope["tools"]["nmap"]:
        commands.append([
            "nmap", "-sV", "--version-light", "-T2", "--top-ports", "1000",
            "--max-retries", "2", "--host-timeout", "20m", "-oX",
            str(output_dir / "nmap.xml"), *targets,
        ])
    if scope["tools"]["nuclei"]:
        commands.append([
            "nuclei", "-list", str(output_dir / "web_targets.txt"),
            "-tags", "misconfig,exposure,ssl,dns,tech",
            "-exclude-tags", "dos,intrusive,bruteforce,fuzz,headless",
            "-severity", "info,low,medium,high,critical",
            "-rate-limit", str(scope["rate_limit"]), "-concurrency", "5",
            "-timeout", "10", "-retries", "1", "-no-interactsh",
            "-disable-update-check", "-jsonl", "-no-color",
            "-output", str(output_dir / "nuclei.jsonl"),
        ])
    if scope["tools"]["testssl"]:
        commands.append([
            "testssl.sh", "--fast", "--warnings", "batch", "--file",
            str(output_dir / "tls_targets.txt"),
        ])
    return commands


def run_command(command: list[str], log_path: Path, timeout_seconds: int = 3600) -> int:
    """Run tool without a shell, save combined output, and return process status."""
    with log_path.open("w", encoding="utf-8") as log:
        log.write(f"# Started: {now_iso()}\n# Command: {json.dumps(command)}\n\n")
        log.flush()
        try:
            result = subprocess.run(
                command,
                stdout=log,
                stderr=subprocess.STDOUT,
                check=False,
                timeout=timeout_seconds,
                text=True,
                env={**os.environ, "NO_COLOR": "1"},
            )
            log.write(f"\n# Exit code: {result.returncode}\n# Finished: {now_iso()}\n")
            return result.returncode
        except subprocess.TimeoutExpired:
            log.write(f"\n# TIMEOUT after {timeout_seconds} seconds\n# Finished: {now_iso()}\n")
            return 124
        except OSError as exc:
            log.write(f"\n# EXECUTION ERROR: {exc}\n# Finished: {now_iso()}\n")
            return 127


def parse_nmap(xml_path: Path) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    assets: list[dict[str, Any]] = []
    web_targets: list[str] = []
    tls_targets: list[str] = []
    if not xml_path.exists() or xml_path.stat().st_size == 0:
        return assets, web_targets, tls_targets

    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError:
        return assets, web_targets, tls_targets

    tls_ports = {443, 465, 636, 853, 989, 990, 993, 995, 8443, 9443}
    likely_http_ports = {80, 81, 3000, 5000, 7001, 8000, 8008, 8080, 8081, 8888, 9000}
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        address_node = host.find("address[@addrtype='ipv4']")
        if address_node is None:
            continue
        ip = address_node.get("addr", "")
        hostnames = [n.get("name", "") for n in host.findall("hostnames/hostname") if n.get("name")]
        ports_out: list[dict[str, Any]] = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            try:
                port_num = int(port.get("portid", "0"))
            except ValueError:
                continue
            proto = port.get("protocol", "tcp")
            service = port.find("service")
            svc_name = service.get("name", "unknown") if service is not None else "unknown"
            product = service.get("product", "") if service is not None else ""
            version = service.get("version", "") if service is not None else ""
            tunnel = service.get("tunnel", "") if service is not None else ""
            ports_out.append({
                "port": port_num, "protocol": proto, "service": svc_name,
                "product": product, "version": version, "tunnel": tunnel,
            })
            if proto == "tcp":
                if port_num in tls_ports or tunnel == "ssl" or "https" in svc_name:
                    tls_targets.append(f"{ip}:{port_num}")
                if port_num in likely_http_ports or port_num in {443, 8443, 9443} or svc_name in {"http", "https", "http-proxy"}:
                    scheme = "https" if (port_num in tls_ports or tunnel == "ssl" or "https" in svc_name) else "http"
                    web_targets.append(f"{scheme}://{ip}:{port_num}")
        assets.append({"ip": ip, "hostnames": hostnames, "ports": ports_out})

    return assets, sorted(set(web_targets)), sorted(set(tls_targets))


def write_text_list(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument("--scope", type=Path, default=DEFAULT_SCOPE, help="JSON file containing authorized private IP/CIDR scope")
    parser.add_argument("--outdir", type=Path, default=Path("reports"), help="Directory where logs and reports are written")
    parser.add_argument("--execute", action="store_true", help="Actually run scanners (otherwise this is a dry run)")
    parser.add_argument("--confirm-authorized", action="store_true", help="Confirm you own/administer the targets or have written permission")
    parser.add_argument("--request", help="Natural-language request (AI turns it into a limited scan plan)")
    parser.add_argument("--ai-provider", choices=("openai", "anthropic", "gemini"), help="AI provider for --request; defaults to SENTINEL_AI_PROVIDER or openai")
    parser.add_argument("--ai-model", help="Optional provider-specific model name; defaults to provider environment setting")
    parser.add_argument("--version", action="version", version="Sentinel starter 0.2.0")
    args = parser.parse_args()

    try:
        scope = load_scope(args.scope)
    except (ValueError, TypeError) as exc:
        print(f"[BLOCKED] {exc}", file=sys.stderr)
        return 2

    original_scope = dict(scope)
    ai_plan: dict[str, Any] | None = None
    requested_checks: set[str] | None = None
    if args.request:
        try:
            from ai_bridge import plan_request
            ai_plan = plan_request(args.request, provider=args.ai_provider, model=args.ai_model)
            if ai_plan["target"] == "NEEDS_INPUT":
                print("[NEED INPUT] " + (ai_plan.get("clarification") or "Specify the exact authorized private IPv4 host/CIDR."), file=sys.stderr)
                return 4
            if ai_plan["target"] != "CONFIG_SCOPE":
                scope["scope"] = [resolve_requested_target(ai_plan["target"], original_scope)]
            requested_checks = set(ai_plan["checks"])
            if not requested_checks:
                raise ValueError("AI plan selected no checks. No scan was started.")
            # Nuclei/TLS endpoints are discovered from service inventory, so Nmap is needed first.
            if requested_checks.intersection({"nuclei", "tls"}):
                requested_checks.add("nmap")
            original_tools = original_scope["tools"]
            scope["tools"] = {
                "nmap": "nmap" in requested_checks and original_tools["nmap"],
                "nuclei": "nuclei" in requested_checks and original_tools["nuclei"],
                "testssl": "tls" in requested_checks and original_tools["testssl"],
            }
        except (ValueError, RuntimeError, ImportError) as exc:
            print(f"[AI PLAN BLOCKED] {exc}", file=sys.stderr)
            return 4

    tools = discover_tool_paths()
    args.outdir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = args.outdir / f"scan-{stamp}"
    run_dir.mkdir(parents=True, exist_ok=True)
    if ai_plan:
        (run_dir / "request_plan.json").write_text(json.dumps({
            **ai_plan,
            "request": args.request,
            "configured_scope": original_scope["scope"],
            "effective_scope": scope["scope"],
            "configured_tools": original_scope["tools"],
            "effective_tools": scope["tools"],
            "note": "LLM output is an untrusted plan; target and action values were validated locally. API requests transmit the user's prompt to the selected provider."
        }, indent=2), encoding="utf-8")

    print(f"{APP_NAME} — starter 0.2.0")
    print(f"Scope file: {args.scope}")
    print("Authorized scope:")
    for item in scope["scope"]:
        print(f"  - {item}")
    if ai_plan:
        print("AI interpretation:")
        print(f"  - Provider/model: {ai_plan['provider']} / {ai_plan['model']}")
        print(f"  - Rationale: {ai_plan['rationale'] or '(none supplied)'}")
        print(f"  - Requested checks: {', '.join(ai_plan['checks'])}")
        print(f"  - Target decision: {ai_plan['target']}")
        print("  - Note: configured tool switches and local scope remain authoritative.")
    print("Tool availability:")
    for name, path in tools.items():
        print(f"  - {name}: {path or 'NOT INSTALLED'}")

    plan = planned_commands(scope, run_dir)
    print("Planned commands (review before execution):")
    for command in plan:
        print("  $ " + " ".join(command))

    if not args.execute:
        print("\n[DRY RUN] No network traffic was sent. Add --execute --confirm-authorized only after checking your written scope.")
        return 0

    try:
        require_authorization(scope, args)
    except PermissionError as exc:
        print(f"[BLOCKED] {exc}", file=sys.stderr)
        return 3

    enabled_tools = scope["tools"]
    for tool_key, binary_key in (("nmap", "nmap"), ("nuclei", "nuclei"), ("testssl", "testssl.sh")):
        if enabled_tools.get(tool_key) and not tools.get(binary_key):
            print(f"[SKIP] {tool_key}: required binary not installed.")

    result_summary: dict[str, Any] = {
        "agent": APP_NAME,
        "version": "0.2.0",
        "started_at": now_iso(),
        "scope": scope["scope"],
        "authorization_confirmed": True,
        "ai_plan": ai_plan,
        "tools": {},
        "assets": [],
        "note": "Detection only; findings require validation. No exploitation or credential testing is performed.",
    }

    nmap_xml = run_dir / "nmap.xml"
    if enabled_tools["nmap"] and tools["nmap"]:
        command = [
            tools["nmap"], "-sV", "--version-light", "-T2", "--top-ports", "1000",
            "--max-retries", "2", "--host-timeout", "20m", "-oX", str(nmap_xml), *scope["scope"],
        ]
        code = run_command(command, run_dir / "nmap.log", timeout_seconds=7200)
        result_summary["tools"]["nmap"] = {"exit_code": code, "log": "nmap.log", "xml": "nmap.xml"}
        assets, web_targets, tls_targets = parse_nmap(nmap_xml)
        result_summary["assets"] = assets
        write_text_list(run_dir / "web_targets.txt", web_targets)
        write_text_list(run_dir / "tls_targets.txt", tls_targets)
        print(f"[DONE] Nmap exit={code}; assets={len(assets)}; web targets={len(web_targets)}; TLS targets={len(tls_targets)}")
    else:
        web_targets, tls_targets = [], []

    if enabled_tools["nuclei"] and tools["nuclei"]:
        target_file = run_dir / "web_targets.txt"
        if target_file.exists() and target_file.read_text(encoding="utf-8").strip():
            command = [
                tools["nuclei"], "-list", str(target_file),
                "-tags", "misconfig,exposure,ssl,dns,tech",
                "-exclude-tags", "dos,intrusive,bruteforce,fuzz,headless",
                "-severity", "info,low,medium,high,critical",
                "-rate-limit", str(scope["rate_limit"]), "-concurrency", "5",
                "-timeout", "10", "-retries", "1", "-no-interactsh",
                "-disable-update-check", "-jsonl", "-no-color", "-output", str(run_dir / "nuclei.jsonl"),
            ]
            code = run_command(command, run_dir / "nuclei.log", timeout_seconds=7200)
            result_summary["tools"]["nuclei"] = {"exit_code": code, "log": "nuclei.log", "output": "nuclei.jsonl"}
        else:
            result_summary["tools"]["nuclei"] = {"skipped": "No web targets identified by Nmap."}

    if enabled_tools["testssl"] and tools["testssl.sh"]:
        target_file = run_dir / "tls_targets.txt"
        if target_file.exists() and target_file.read_text(encoding="utf-8").strip():
            command = [tools["testssl.sh"], "--fast", "--warnings", "batch", "--file", str(target_file)]
            code = run_command(command, run_dir / "testssl.log", timeout_seconds=14400)
            result_summary["tools"]["testssl"] = {"exit_code": code, "log": "testssl.log"}
        else:
            result_summary["tools"]["testssl"] = {"skipped": "No TLS targets identified by Nmap."}

    result_summary["finished_at"] = now_iso()
    (run_dir / "summary.json").write_text(json.dumps(result_summary, indent=2), encoding="utf-8")
    print(f"\nReport: {run_dir / 'summary.json'}")
    print("Review logs and validate findings manually before remediation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
