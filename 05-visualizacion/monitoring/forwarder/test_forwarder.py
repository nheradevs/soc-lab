#!/usr/bin/env python3
"""Behaviour tests for the Telegram forwarder (stdlib unittest only).

Run from this directory:

    python3 -m unittest -v test_forwarder
"""

import importlib.util
import itertools
import os
import unittest
from unittest import mock

MODULE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "forwarder.py")

_counter = itertools.count()

# Ambient env that must not leak into the freshly imported module: every load
# pins the source URL and starts from the documented defaults.
_BASE_ENV = {
    "OPENSEARCH_URL": "https://localhost:9200",
    "DRY_RUN": "true",
}


def load_forwarder(env=None):
    """Import forwarder.py into a fresh module object for one test."""
    name = "_forwarder_under_test_%d" % next(_counter)
    spec = importlib.util.spec_from_file_location(name, MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    with mock.patch.dict(os.environ, _BASE_ENV):
        os.environ.pop("RULES", None)
        os.environ.pop("INDEXER_CA_FILE", None)
        os.environ.update(env or {})
        spec.loader.exec_module(module)
    return module


class DefaultRulesTest(unittest.TestCase):
    """S6: the lab's most severe detections are forwarded by default."""

    def test_default_rules_include_high_severity_detections(self):
        module = load_forwarder()
        self.assertEqual(
            module.RULES,
            ["100501", "100504", "100503", "100510", "100523", "501", "502"],
        )

    def test_rules_env_override_still_wins(self):
        """PRESERVE: an explicit RULES env value keeps overriding the default."""
        module = load_forwarder({"RULES": "501,502"})
        self.assertEqual(module.RULES, ["501", "502"])


class IsInternalHostTest(unittest.TestCase):
    """S7: only loopback and the 100.64.0.0/10 tailnet range are internal."""

    @classmethod
    def setUpClass(cls):
        cls.module = load_forwarder()

    def test_accepts_loopback_and_tailnet(self):
        accepted = (
            "localhost",
            "127.0.0.1",
            "::1",
            "https://localhost:9200",
            "https://127.0.0.1:9200",
            "https://[::1]:9200",
            "https://100.64.0.1:9200",
            "https://100.127.255.254:9200",
        )
        for url in accepted:
            with self.subTest(url=url):
                self.assertTrue(self.module._is_internal_host(url))

    def test_rejects_public_and_lookalike_hosts(self):
        rejected = (
            "https://100.24.1.5:9200",
            "https://100.evil.com:9200",
            "https://100.128.0.1:9200",
            "https://example.com:9200",
        )
        for url in rejected:
            with self.subTest(url=url):
                self.assertFalse(self.module._is_internal_host(url))


class BuildMessageEscapingTest(unittest.TestCase):
    """S8: attacker-controlled credentials must not break the Telegram HTML."""

    @classmethod
    def setUpClass(cls):
        cls.module = load_forwarder()

    @staticmethod
    def _event(password, src_ip="203.0.113.7", username="root"):
        return {
            "rule": {"id": "100501", "level": 10, "description": "Cowrie fake login"},
            "data": {
                "src_ip": src_ip,
                "username": username,
                "password": password,
                "protocol": "ssh",
                "dst_port": 2222,
            },
            "@timestamp": "2026-10-20T12:34:56Z",
        }

    def test_angle_bracket_password_is_escaped(self):
        msg = self.module.build_message(self._event("<b>&x"))
        self.assertNotIn("<", msg)
        self.assertIn("&lt;", msg)
        # Masked shape of "<b>&x" is "<***x"
        self.assertIn("&lt;***x", msg)
        self.assertNotIn("<b>", msg)

    def test_ampersand_password_is_escaped(self):
        msg = self.module.build_message(self._event("<abc&"))
        self.assertNotIn("<", msg)
        self.assertNotIn("&", msg.replace("&lt;", "").replace("&amp;", ""))
        self.assertIn("&lt;***&amp;", msg)

    def test_normal_event_still_carries_masked_credential_and_source_ip(self):
        """PRESERVE: a benign 100501 alert keeps its masked credential and IP."""
        msg = self.module.build_message(self._event("hunter2", src_ip="198.51.100.42"))
        self.assertIsNotNone(msg)
        self.assertIn("h*****2", msg)
        self.assertIn("198.51.100.42", msg)
        self.assertNotIn("hunter2", msg)


if __name__ == "__main__":
    unittest.main()
