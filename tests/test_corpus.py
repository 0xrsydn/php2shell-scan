import unittest

from php2shell_scan import corpus
from php2shell_scan.report import surface_verdict, compare_verdict, EXIT
from php2shell_scan.transport import classify


class TestCorpus(unittest.TestCase):
    def test_every_case_parses_as_multipart(self):
        """A body PHP silently ignores proves nothing: check structure, not just bytes."""
        from email import policy
        from email.parser import BytesParser
        for name, hdr, body in corpus.corpus(heavy=True):
            with self.subTest(case=name):
                ct = hdr["Content-Type"]
                self.assertTrue(ct.startswith("multipart/form-data; boundary="))
                raw = b"Content-Type: " + ct.encode() + b"\r\n\r\n" + body
                msg = BytesParser(policy=policy.HTTP).parsebytes(raw)
                parts = list(msg.iter_parts())
                if name == "no-final-boundary":
                    self.assertGreaterEqual(len(parts), 1)
                else:
                    self.assertGreaterEqual(len(parts), 1, f"{name} produced no parts")

    def test_boundary_quoting(self):
        for bnd, quoted in (("plain123", False), ('a"b', True), ("a=b?c", True)):
            _, hdr, _ = corpus.build("t", [corpus.part("a", "v")], bnd=bnd)
            self.assertEqual(quoted, hdr["Content-Type"].split("boundary=")[1].startswith('"'))

    def test_many_files_crosses_default_limit(self):
        _, _, body = corpus.case("many-files")
        self.assertEqual(body.count(b'filename="'), 25)

    def test_unknown_case(self):
        with self.assertRaises(KeyError):
            corpus.case("nope")


class TestClassify(unittest.TestCase):
    def test_classes(self):
        self.assertEqual(classify(200), "ok")
        self.assertEqual(classify(302), "ok")
        self.assertEqual(classify(405), "client")
        self.assertEqual(classify(419), "client")
        self.assertEqual(classify(403), "client")
        self.assertEqual(classify(429), "throttle")
        self.assertEqual(classify(500), "server")
        self.assertEqual(classify(503), "server")


class TestVerdicts(unittest.TestCase):
    def test_blocked_is_mitigated(self):
        v = surface_verdict(True, "client", 403, "client")
        self.assertEqual(v["verdict"], "mitigated")
        self.assertEqual(v["exit_code"], 0)

    def test_parsed_is_exposed(self):
        self.assertEqual(surface_verdict(True, "ok", 302, "ok",
                                         multipart_evidence=True)["verdict"], "exposed")
        self.assertEqual(surface_verdict(True, "client", 405, "client",
                                         multipart_evidence=True)["verdict"], "exposed")
        self.assertEqual(surface_verdict(True, "client", 419, "client",
                                         multipart_evidence=True)["verdict"], "exposed")

    def test_status_without_php_evidence_is_inconclusive(self):
        # A static nginx returns 405 for POST /; that is not the CVE surface.
        for code, r in ((405, "client"), (200, "ok"), (302, "ok"), (419, "client")):
            with self.subTest(code=code):
                v = surface_verdict(True, r, code, r, multipart_evidence=False)
                self.assertEqual(v["verdict"], "inconclusive")

    def test_throttle_is_not_exposed(self):
        v = surface_verdict(True, "throttle", 429, "throttle")
        self.assertEqual(v["verdict"], "inconclusive")

    def test_no_php_is_inconclusive(self):
        self.assertEqual(surface_verdict(False, "ok", 200, "ok")["verdict"], "inconclusive")

    def test_fix_lookalike_improvement(self):
        v = compare_verdict({}, {}, [], old_deaths=3, new_deaths=0)
        self.assertEqual(v["verdict"], "improved")
        self.assertEqual(EXIT[v["verdict"]], 0)

    def test_unchanged_when_deaths_persist(self):
        v = compare_verdict({}, {}, [], old_deaths=2, new_deaths=2)
        self.assertEqual(v["verdict"], "unchanged")

    def test_flat_profile_is_no_signal(self):
        self.assertEqual(compare_verdict({}, {}, [], 0, 0)["verdict"], "no_signal")

    def test_changed_cases(self):
        self.assertEqual(compare_verdict({}, {}, ["a"], 0, 0)["verdict"], "changed")


if __name__ == "__main__":
    unittest.main()
