import tempfile
import unittest
from pathlib import Path

from netauditor.inventory import InventoryError, _load_plain, _load_yaml

YAML_GROUPED = """\
defaults:
  username: globaluser
  password: globalpass
groups:
  sydenham:
    defaults:
      username: syduser
    hosts:
      - host: 10.1.0.11
        name: sy-sw-1
      - host: 10.1.0.12
  delahey:
    hosts:
      - host: 10.2.0.11
        name: de-sw-1
        password: inlinepass
hosts:
  - host: 10.9.0.1
    name: ungrouped-sw
  - host: 10.9.0.2
    group: kingspark
"""

PLAIN_GROUPED = """\
# ungrouped first
10.9.0.1

[sydenham]
10.1.0.11
10.1.0.12,localadmin,localpass

[delahey]
10.2.0.11
"""


def write_tmp(content, suffix):
    f = tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False, encoding="utf-8")
    f.write(content)
    f.close()
    return Path(f.name)


class TestYamlGroups(unittest.TestCase):
    def setUp(self):
        self.path = write_tmp(YAML_GROUPED, ".yml")
        self.hosts = {h.host: h for h in _load_yaml(self.path)}

    def tearDown(self):
        self.path.unlink()

    def test_group_membership(self):
        self.assertEqual(self.hosts["10.1.0.11"].group, "sydenham")
        self.assertEqual(self.hosts["10.2.0.11"].group, "delahey")
        self.assertEqual(self.hosts["10.9.0.1"].group, "")

    def test_per_host_group_key(self):
        self.assertEqual(self.hosts["10.9.0.2"].group, "kingspark")

    def test_credential_precedence(self):
        # group defaults override global defaults; inline overrides both
        self.assertEqual(self.hosts["10.1.0.11"].username, "syduser")
        self.assertEqual(self.hosts["10.1.0.11"].password, "globalpass")
        self.assertEqual(self.hosts["10.2.0.11"].password, "inlinepass")
        self.assertEqual(self.hosts["10.9.0.1"].username, "globaluser")

    def test_all_hosts_loaded(self):
        self.assertEqual(len(self.hosts), 5)


class TestPlainGroups(unittest.TestCase):
    def setUp(self):
        self.path = write_tmp(PLAIN_GROUPED, ".txt")
        self.hosts = {h.host: h for h in _load_plain(self.path)}

    def tearDown(self):
        self.path.unlink()

    def test_sections_assign_groups(self):
        self.assertEqual(self.hosts["10.9.0.1"].group, "")
        self.assertEqual(self.hosts["10.1.0.11"].group, "sydenham")
        self.assertEqual(self.hosts["10.1.0.12"].group, "sydenham")
        self.assertEqual(self.hosts["10.2.0.11"].group, "delahey")

    def test_inline_creds_still_parse(self):
        self.assertEqual(self.hosts["10.1.0.12"].username, "localadmin")
        self.assertEqual(self.hosts["10.1.0.12"].password, "localpass")


if __name__ == "__main__":
    unittest.main()
