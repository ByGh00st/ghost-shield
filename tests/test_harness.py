#!/usr/bin/env python3
"""
Unit and boundary security tests for the Aegis / Hydra flood test harness and config.
"""

import ipaddress
import json
import os
import socket
import unittest

import test_flood


class TestFloodSecurityBoundaries(unittest.TestCase):
    def test_calc_checksum_known_vectors(self):
        # Empty payload
        self.assertEqual(test_flood.calc_checksum(b""), 0xFFFF)
        # Even length
        chk_even = test_flood.calc_checksum(b"\x45\x00\x00\x3c")
        self.assertIsInstance(chk_even, int)
        self.assertTrue(0 <= chk_even <= 0xFFFF)
        # Odd length (zero padded at end per RFC 1071)
        chk_odd = test_flood.calc_checksum(b"\x45\x00\x00")
        self.assertIsInstance(chk_odd, int)
        self.assertTrue(0 <= chk_odd <= 0xFFFF)

    def test_authorized_lab_ip_allows_private_and_documentation(self):
        authorized_ips = [
            "127.0.0.1",
            "127.42.0.1",
            "10.0.0.1",
            "10.254.12.34",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.1",
            "192.168.100.200",
            "169.254.1.1",
            "192.0.2.1",       # RFC 5737 TEST-NET-1
            "198.51.100.42",   # RFC 5737 TEST-NET-2
            "203.0.113.99",    # RFC 5737 TEST-NET-3
            "198.18.0.1",      # RFC 2544 Benchmarking
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",     # RFC 3849 Documentation
        ]
        for raw in authorized_ips:
            ip_obj = ipaddress.ip_address(raw)
            self.assertTrue(
                test_flood.is_authorized_lab_ip(ip_obj),
                f"Expected authorized lab IP: {raw}",
            )

    def test_authorized_lab_ip_blocks_public_and_multicast(self):
        prohibited_ips = [
            "8.8.8.8",
            "1.1.1.1",
            "142.250.190.46",
            "224.0.0.1",       # Multicast
            "239.255.255.250", # Multicast
            "255.255.255.255", # Global Broadcast
            "0.0.0.0",         # Unspecified
            "::",              # IPv6 Unspecified
            "ff02::1",         # IPv6 Multicast
        ]
        for raw in prohibited_ips:
            ip_obj = ipaddress.ip_address(raw)
            self.assertFalse(
                test_flood.is_authorized_lab_ip(ip_obj),
                f"Expected public/illegal IP to be rejected: {raw}",
            )

    def test_resolve_and_validate_target_security_enforcement(self):
        # Permitted lab targets
        self.assertEqual(
            test_flood.resolve_and_validate_target("127.0.0.1", socket.AF_INET),
            "127.0.0.1",
        )
        self.assertEqual(
            test_flood.resolve_and_validate_target("192.168.1.1", socket.AF_INET),
            "192.168.1.1",
        )

        # Prohibited targets MUST raise PermissionError
        with self.assertRaises(PermissionError):
            test_flood.resolve_and_validate_target("8.8.8.8", socket.AF_INET)

        with self.assertRaises(PermissionError):
            test_flood.resolve_and_validate_target("1.1.1.1", socket.AF_INET)

        # Family mismatch
        with self.assertRaises(ValueError):
            test_flood.resolve_and_validate_target("127.0.0.1", socket.AF_INET6)


class TestAegisConfigurationIntegrity(unittest.TestCase):
    def test_config_json_schema_and_invariants(self):
        config_path = os.path.join(os.path.dirname(__file__), "..", "config.json")
        self.assertTrue(os.path.exists(config_path), "config.json must exist in root")

        with open(config_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)

        required_keys = [
            "checkers",
            "global_alert_pps",
            "panic_mode_limit",
            "normal_mode_limit",
            "ban_duration_sec",
            "arp_mode_limit",
            "mac_mode_limit",
        ]
        for key in required_keys:
            self.assertIn(key, cfg, f"Missing required configuration key '{key}'")

        self.assertGreater(cfg["global_alert_pps"], 0)
        self.assertGreater(cfg["panic_mode_limit"], 0)
        self.assertGreater(cfg["normal_mode_limit"], 0)
        self.assertLess(
            cfg["panic_mode_limit"],
            cfg["normal_mode_limit"],
            "panic_mode_limit must be strictly less than normal_mode_limit",
        )
        self.assertGreater(cfg["ban_duration_sec"], 0)
        self.assertGreater(cfg["arp_mode_limit"], 0)
        self.assertGreater(cfg["mac_mode_limit"], 0)
        self.assertIsInstance(cfg["checkers"], list)


if __name__ == "__main__":
    unittest.main()
