import unittest

from netauditor import checks, parsers

SSH_V2 = """\
SSH Enabled - version 2.0
Authentication methods:publickey,keyboard-interactive,password
Authentication timeout: 120 secs; Authentication retries: 3
Minimum expected Diffie Hellman key size : 1024 bits
"""

SSH_199 = """\
SSH Enabled - version 1.99
Authentication timeout: 120 secs; Authentication retries: 3
"""

SSH_V1_ONLY = "SSH Enabled - version 1.5\nAuthentication timeout: 120 secs\n"

SSH_DISABLED = "SSH Disabled - version 2.0\n%Please create RSA keys to enable SSH.\n"

SSH_UNSUPPORTED = "% Invalid input detected at '^' marker.\n"

CONFIG_WITHOUT = "hostname sw1\nline vty 0 4\n transport input ssh\nend\n"
CONFIG_WITH = "hostname sw1\nip ssh version 2\nline vty 0 4\n transport input ssh\nend\n"


def codes_for(config, ssh_output):
    report = checks.build_host_report({
        "host": "10.0.0.1", "name": "sw1", "error": None,
        "outputs": {"running_config": config, "ip_ssh": ssh_output}})
    return {f["code"]: f for f in report["findings"]}


class TestParseIpSsh(unittest.TestCase):
    def test_v2(self):
        parsed = parsers.parse_ip_ssh(SSH_V2)
        self.assertTrue(parsed["available"])
        self.assertTrue(parsed["enabled"])
        self.assertEqual(parsed["version"], "2.0")

    def test_199(self):
        self.assertEqual(parsers.parse_ip_ssh(SSH_199)["version"], "1.99")

    def test_disabled(self):
        parsed = parsers.parse_ip_ssh(SSH_DISABLED)
        self.assertTrue(parsed["available"])
        self.assertFalse(parsed["enabled"])

    def test_unsupported_command(self):
        self.assertFalse(parsers.parse_ip_ssh(SSH_UNSUPPORTED)["available"])

    def test_empty(self):
        self.assertFalse(parsers.parse_ip_ssh("")["available"])


class TestSshFindings(unittest.TestCase):
    def test_v2_runtime_clears_the_warning_even_without_config_line(self):
        """The bug: a switch already running v2 was warned about forever."""
        self.assertNotIn("SSH_V1", codes_for(CONFIG_WITHOUT, SSH_V2))

    def test_199_is_warned_even_though_config_looks_fine(self):
        found = codes_for(CONFIG_WITH, SSH_199)
        self.assertIn("SSH_V1", found)
        self.assertEqual(found["SSH_V1"]["severity"], "warning")
        self.assertIn("1.99", found["SSH_V1"]["message"])

    def test_v1_only(self):
        found = codes_for(CONFIG_WITHOUT, SSH_V1_ONLY)
        self.assertEqual(found["SSH_V1"]["severity"], "warning")

    def test_disabled_is_its_own_finding(self):
        found = codes_for(CONFIG_WITHOUT, SSH_DISABLED)
        self.assertIn("SSH_DISABLED", found)
        self.assertEqual(found["SSH_DISABLED"]["severity"], "warning")
        self.assertNotIn("SSH_V1", found)

    def test_fallback_is_info_when_command_unavailable(self):
        found = codes_for(CONFIG_WITHOUT, SSH_UNSUPPORTED)
        self.assertIn("SSH_V1", found)
        self.assertEqual(found["SSH_V1"]["severity"], "info")
        self.assertIn("could not be confirmed", found["SSH_V1"]["message"])

    def test_fallback_quiet_when_config_pins_v2(self):
        self.assertNotIn("SSH_V1", codes_for(CONFIG_WITH, SSH_UNSUPPORTED))

    def test_missing_output_entirely_behaves_like_unavailable(self):
        report = checks.build_host_report({
            "host": "10.0.0.1", "name": "sw1", "error": None,
            "outputs": {"running_config": CONFIG_WITHOUT}})
        found = {f["code"]: f for f in report["findings"]}
        self.assertEqual(found["SSH_V1"]["severity"], "info")


if __name__ == "__main__":
    unittest.main()
