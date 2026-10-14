#!/usr/bin/env python3
"""Small provider bridge used only to turn natural language into a strict scan plan.

The model never returns shell commands. Its output is parsed as JSON and checked
against a local allowlist/scope before any scanner is invoked.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

PROVIDERS = {"openai", "anthropic", "gemini"}
ACTIONS = {"nmap", "nuclei", "tls"}

SYSTEM_PROMPT = """You are the planning component for Sentinel, a defensive vulnerability-assessment tool.
Return JSON only with exactly these keys:
- target: one IPv4 address, one IPv4 CIDR, CONFIG_SCOPE, or NEEDS_INPUT
- checks: array containing only nmap, nuclei, tls
- rationale: short plain-language explanation
- clarification: short question if target is NEEDS_INPUT, otherwise empty string

Rules:
1) Never propose shell commands, exploit steps, credential attacks, brute-force, denial-of-service, persistence, stealth/evasion, or internet-wide scanning.
2) Use a specific IPv4 host/CIDR only when it appears in the user's request.
3) Use CONFIG_SCOPE only if the user explicitly requests the configured/authorized scope or entire configured private lab network.
4) If a host/network is missing or ambiguous, use NEEDS_INPUT.
5) For ordinary host/service discovery use nmap. For low-impact web misconfiguration/exposure checks use nuclei. For TLS configuration checks use tls. Pick only what the user requested; a broad defensive vulnerability assessment may select all three.
6) This JSON is only a plan; the local controller will enforce authorization, configured scope, tool enablement and confirmation.
"""


def _request_json(url: str, headers: dict[str, str], payload: dict[str, Any]) -> dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers={**headers, "Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            raw = response.read(2_000_000).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        detail = exc.read(4000).decode("utf-8", errors="replace")
        raise RuntimeError(f"AI provider returned HTTP {exc.code}: {detail}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError(f"Could not contact the AI provider: {exc}") from exc
    try:
        result = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("AI provider returned a non-JSON API response.") from exc
    if not isinstance(result, dict):
        raise RuntimeError("AI provider returned an unexpected response shape.")
    return result


def _extract_plan_text(provider: str, response: dict[str, Any]) -> str:
    try:
        if provider == "openai":
            return response["choices"][0]["message"]["content"]
        if provider == "anthropic":
            return "\n".join(block["text"] for block in response["content"] if block.get("type") == "text")
        if provider == "gemini":
            candidates = response.get("candidates", [])
            parts = candidates[0]["content"]["parts"]
            return "\n".join(part["text"] for part in parts if isinstance(part.get("text"), str))
    except (KeyError, IndexError, TypeError) as exc:
        raise RuntimeError(f"Unexpected {provider} response format.") from exc
    raise RuntimeError(f"Unsupported AI provider: {provider}")


def plan_request(user_request: str, provider: str | None = None, model: str | None = None) -> dict[str, Any]:
    """Ask the selected LLM for a constrained plan, never for executable commands."""
    provider = (provider or os.getenv("SENTINEL_AI_PROVIDER", "openai")).strip().lower()
    if provider not in PROVIDERS:
        raise ValueError(f"Unsupported provider {provider!r}; choose one of: {', '.join(sorted(PROVIDERS))}.")
    if not user_request.strip():
        raise ValueError("Request text cannot be empty.")

    if provider == "openai":
        api_key = os.getenv("OPENAI_API_KEY")
        model = model or os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY is not set. Configure an API key locally; never commit it to GitHub.")
        response = _request_json(
            "https://api.openai.com/v1/chat/completions",
            {"Authorization": f"Bearer {api_key}"},
            {"model": model, "temperature": 0, "response_format": {"type": "json_object"},
             "messages": [{"role": "system", "content": SYSTEM_PROMPT + " Output a valid JSON object."},
                          {"role": "user", "content": user_request}]},
        )
    elif provider == "anthropic":
        api_key = os.getenv("ANTHROPIC_API_KEY")
        model = model or os.getenv("ANTHROPIC_MODEL", "claude-3-7-sonnet-latest")
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY is not set. Configure an API key locally; never commit it to GitHub.")
        response = _request_json(
            "https://api.anthropic.com/v1/messages",
            {"x-api-key": api_key, "anthropic-version": "2023-06-01"},
            {"model": model, "max_tokens": 350, "temperature": 0,
             "system": SYSTEM_PROMPT + " Output a valid JSON object.",
             "messages": [{"role": "user", "content": user_request}]},
        )
    else:
        api_key = os.getenv("GEMINI_API_KEY")
        model = model or os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
        if not api_key:
            raise RuntimeError("GEMINI_API_KEY is not set. Configure an API key locally; never commit it to GitHub.")
        encoded_model = urllib.parse.quote(model.removeprefix("models/"), safe="-._")
        response = _request_json(
            f"https://generativelanguage.googleapis.com/v1beta/models/{encoded_model}:generateContent",
            {"x-goog-api-key": api_key},
            {"systemInstruction": {"parts": [{"text": SYSTEM_PROMPT + " Output a valid JSON object."}]},
             "contents": [{"role": "user", "parts": [{"text": user_request}]}],
             "generationConfig": {"temperature": 0, "responseMimeType": "application/json", "maxOutputTokens": 350}},
        )

    text = _extract_plan_text(provider, response)
    try:
        plan = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError("AI output was not valid JSON; no scan was started. Try a more specific request.") from exc
    if not isinstance(plan, dict):
        raise RuntimeError("AI output must be a JSON object; no scan was started.")
    target = plan.get("target")
    checks = plan.get("checks")
    rationale = plan.get("rationale", "")
    clarification = plan.get("clarification", "")
    if not isinstance(target, str) or target not in {"CONFIG_SCOPE", "NEEDS_INPUT"} and not target.strip():
        raise RuntimeError("AI plan has an invalid target; no scan was started.")
    if not isinstance(checks, list) or any(not isinstance(action, str) or action not in ACTIONS for action in checks):
        raise RuntimeError("AI plan contains unsupported checks; no scan was started.")
    if target not in {"CONFIG_SCOPE", "NEEDS_INPUT"} and not checks:
        raise RuntimeError("AI plan selected no checks; no scan was started.")
    if not isinstance(rationale, str) or not isinstance(clarification, str):
        raise RuntimeError("AI plan text fields are invalid; no scan was started.")
    return {"provider": provider, "model": model, "target": target.strip(),
            "checks": sorted(set(checks)), "rationale": rationale[:500], "clarification": clarification[:500]}
