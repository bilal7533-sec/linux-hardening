import json
import tempfile
import unittest
from pathlib import Path

from sentinel_agent import load_scope


class ScopeValidationTests(unittest.TestCase):
    def write_config(self, scope_values):
        tmp = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", suffix=".json", delete=False)
        json.dump({"authorized": False, "scope": scope_values, "tools": {"nmap": True}}, tmp)
        tmp.close()
        self.addCleanup(lambda: Path(tmp.name).unlink(missing_ok=True))
        return Path(tmp.name)

    def test_accepts_private_network(self):
        data = load_scope(self.write_config(["192.168.1.0/24"]))
        self.assertEqual(data["scope"], ["192.168.1.0/24"])

    def test_rejects_public_network(self):
        with self.assertRaises(ValueError):
            load_scope(self.write_config(["8.8.8.0/24"]))

    def test_rejects_oversized_network(self):
        with self.assertRaises(ValueError):
            load_scope(self.write_config(["10.0.0.0/8"]))

    def test_rejects_ipv6_in_starter(self):
        with self.assertRaises(ValueError):
            load_scope(self.write_config(["fd00::/64"]))

    def test_rejects_large_scope_by_default(self):
        with self.assertRaises(ValueError):
            load_scope(self.write_config(["10.0.0.0/16"]))


if __name__ == "__main__":
    unittest.main()
