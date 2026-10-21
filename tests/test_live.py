import json
import os
import unittest

from php2shell_scan import commands, corpus
from php2shell_scan.transport import Client

LIVE = os.environ.get("PHP2SHELL_LIVE")


@unittest.skipUnless(LIVE, "set PHP2SHELL_LIVE=https://host/ to run live checks")
class TestLive(unittest.TestCase):
    """Cheap end-to-end assertions against any PHP front. Keep it to ~15 requests."""

    def setUp(self):
        self.cl = Client(LIVE, delay=0.1, max_requests=60)

    def test_probe_schema(self):
        doc = commands.probe(self.cl)
        self.assertEqual(doc["schema"], "php2shell.scan/1")
        self.assertIn("result", doc)
        self.assertIn(doc["result"]["verdict"]["verdict"],
                      {"mitigated", "exposed", "inconclusive"})

    def test_baseline_compare_roundtrip(self):
        doc = commands.baseline(self.cl, rounds=1, per_case=1, heavy=False, rand_n=2)
        text = json.dumps(doc)
        reloaded = json.loads(text)
        self.assertEqual(reloaded["result"]["php_worker_deaths"],
                         doc["result"]["php_worker_deaths"])

    def test_stress_single_case(self):
        doc = commands.stress(self.cl, cases=["progress"], per_case=1, heavy=False)
        self.assertIn("by_case", doc["result"])


if __name__ == "__main__":
    unittest.main()
