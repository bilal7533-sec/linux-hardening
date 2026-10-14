import json
import os
import unittest
from unittest.mock import patch
from pathlib import Path

from ai_bridge import plan_request
from sentinel_agent import load_scope, resolve_requested_target


class TargetScopeTests(unittest.TestCase):
    def setUp(self):
        self.scope = load_scope(Path("config/scope.json"))
        self.scope["scope"] = ["192.168.149.0/24"]
        self.scope["max_hosts"] = 64

    def test_target_inside_scope_is_allowed(self):
        self.assertEqual(resolve_requested_target("192.168.149.129", self.scope), "192.168.149.129/32")

    def test_target_outside_scope_is_rejected(self):
        with self.assertRaises(ValueError):
            resolve_requested_target("192.168.150.10", self.scope)

    def test_public_target_is_rejected(self):
        with self.assertRaises(ValueError):
            resolve_requested_target("8.8.8.8", self.scope)

    def test_broad_target_above_budget_is_rejected(self):
        with self.assertRaises(ValueError):
            resolve_requested_target("192.168.149.0/24", self.scope)


class AIPlanTests(unittest.TestCase):
    @patch.dict(os.environ, {"OPENAI_API_KEY": "test-key", "OPENAI_MODEL": "test-model"})
    @patch("ai_bridge._request_json")
    def test_openai_plan_is_parsed(self, mock_request):
        mock_request.return_value = {
            "output": [{"type": "message", "content": [{"type": "output_text", "text": json.dumps({
                "target": "192.168.149.129",
                "checks": ["nmap", "tls"],
                "rationale": "Service inventory and TLS checks",
                "clarification": ""
            })}]}]
        }
        plan = plan_request("Scan 192.168.149.129 and check TLS", provider="openai")
        self.assertEqual(plan["target"], "192.168.149.129")
        self.assertEqual(plan["checks"], ["nmap", "tls"])
        mock_request.assert_called_once()

    @patch.dict(os.environ, {"OPENAI_API_KEY": "test-key", "OPENAI_MODEL": "test-model"})
    @patch("ai_bridge._request_json")
    def test_unsupported_action_is_rejected(self, mock_request):
        mock_request.return_value = {
            "output": [{"type": "message", "content": [{"type": "output_text", "text": json.dumps({
                "target": "192.168.149.129", "checks": ["run-shell"],
                "rationale": "bad action", "clarification": ""
            })}]}]
        }
        with self.assertRaises(RuntimeError):
            plan_request("Please do something", provider="openai")

    def test_unknown_provider_is_rejected(self):
        with self.assertRaises(ValueError):
            plan_request("Scan a host", provider="some-random-provider")


if __name__ == "__main__":
    unittest.main()
