import unittest

from netauditor.connect import match_hosts
from netauditor.inventory import Host

HOSTS = [
    Host(host="10.1.0.11", name="sy-sw-core-1", group="sydenham"),
    Host(host="10.1.0.12", name="sy-sw-lib-1", group="sydenham"),
    Host(host="10.2.0.11", name="de-sw-lib-2", group="delahey"),
    Host(host="10.2.0.12", name="", group="delahey"),
]


class TestMatchHosts(unittest.TestCase):
    def test_exact_ip_wins(self):
        matches = match_hosts(HOSTS, "10.1.0.11")
        self.assertEqual([h.name for h in matches], ["sy-sw-core-1"])

    def test_exact_name_wins_over_substring(self):
        # "sy-sw-lib-1" is also a substring-match for core-1's group etc.
        matches = match_hosts(HOSTS, "sy-sw-lib-1")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].host, "10.1.0.12")

    def test_substring_matches_multiple(self):
        matches = match_hosts(HOSTS, "lib")
        self.assertEqual({h.host for h in matches}, {"10.1.0.12", "10.2.0.11"})

    def test_group_substring(self):
        matches = match_hosts(HOSTS, "delahey")
        self.assertEqual({h.host for h in matches}, {"10.2.0.11", "10.2.0.12"})

    def test_case_insensitive(self):
        matches = match_hosts(HOSTS, "SY-SW-CORE-1")
        self.assertEqual(len(matches), 1)

    def test_empty_target_returns_all(self):
        self.assertEqual(len(match_hosts(HOSTS, "")), len(HOSTS))

    def test_no_match(self):
        self.assertEqual(match_hosts(HOSTS, "kingspark"), [])

    def test_nameless_host_matches_by_ip(self):
        matches = match_hosts(HOSTS, "10.2.0.12")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].display_name(), "10.2.0.12")


if __name__ == "__main__":
    unittest.main()
