import contextlib
import io
import json
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from php2shell_scan import bulk
from php2shell_scan.cli import main
from php2shell_scan.commands import probe
from php2shell_scan.transport import Client


class _Handler(BaseHTTPRequestHandler):
    php = False

    def _reply(self, code, body=b"ok"):
        self.send_response(code)
        if self.php:
            self.send_header("X-Powered-By", "PHP/8.3.0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/php2shell-scan-control-404"):
            return self._reply(404, b"")
        if self.path.startswith("/index.php") and not self.php:
            return self._reply(404, b"")
        return self._reply(200)

    def do_POST(self):
        remaining = int(self.headers.get("Content-Length") or 0)
        while remaining > 0:
            chunk = self.rfile.read(min(65536, remaining))
            if not chunk:
                break
            remaining -= len(chunk)
        return self._reply(405, b"")

    def log_message(self, format, *args):
        pass

    def handle_error(self):
        pass


class _PhpHandler(_Handler):
    php = True


class _SourceHandler(_Handler):
    """Misconfigured static server: /index.php is served as source, not executed."""

    def do_GET(self):
        if self.path.startswith("/index.php"):
            return self._reply(200, b"<?php echo 'x'; ?>")
        return super().do_GET()


class _SlowHandler(_Handler):
    def do_GET(self):
        time.sleep(5)
        return self._reply(200)


@contextlib.contextmanager
def _server(handler=_Handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    srv.daemon_threads = True
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield srv
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(2)


class TestTargets(unittest.TestCase):
    def test_normalize(self):
        cases = {
            "example.com": "https://example.com",
            "https://example.com/": "https://example.com",
            "HTTP://example.com:8080/app/": "http://example.com:8080/app",
            "example.com/app": "https://example.com/app",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(bulk.normalize_target(raw), expected)

    def test_rejects_bad_targets(self):
        for raw in ("ftp://example.com", "https://", "https://example.com/?a=1",
                    "https://example.com/#frag", "https://example.com:bad", "*.example.com",
                    "https://exa mple.com"):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    bulk.normalize_target(raw)

    def test_load_dedupes_and_reports_invalid(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "targets.txt"
            path.write_text("# scan list\nexample.com\nhttps://example.com/\n\nftp://bad\n"
                            "example.org # inline comment\n")
            result = bulk.load_targets(str(path))
        self.assertEqual(result.targets, ["https://example.com", "https://example.org"])
        self.assertEqual(result.duplicates, 1)
        self.assertEqual(len(result.invalid), 1)
        self.assertEqual(result.invalid[0]["line"], 5)

    def test_aggregate_exit(self):
        ok = {"exit_code": 0, "status": "ok"}
        exposed = {"exit_code": 1, "status": "ok"}
        unproven = {"exit_code": 2, "status": "ok"}
        timeout = {"exit_code": None, "status": "timeout"}
        self.assertEqual(bulk.aggregate_exit([ok, ok]), 0)
        self.assertEqual(bulk.aggregate_exit([ok, exposed, unproven]), 1)
        self.assertEqual(bulk.aggregate_exit([ok, unproven]), 2)
        self.assertEqual(bulk.aggregate_exit([ok, timeout]), 2)


class TestBulkCLI(unittest.TestCase):
    def test_scans_multiple_targets_and_writes_consolidated_results(self):
        with _server(_PhpHandler) as srv, tempfile.TemporaryDirectory() as tmp:
            port = srv.server_address[1]
            targets = Path(tmp) / "targets.txt"
            targets.write_text(f"# list\n"
                               f"http://127.0.0.1:{port}/\n"
                               f"http://127.0.0.1:{port}/app\n"
                               f"http://127.0.0.1:{port}\n"
                               f"ftp://bad\n")
            out = Path(tmp) / "out"
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = main(["bulk", str(targets), "--out", str(out), "--format", "json",
                             "--quiet", "--delay", "0", "--host-delay", "0",
                             "--host-timeout", "30", "--workers", "2", "--quick"])
            self.assertEqual(code, 1, stderr.getvalue())
            doc = json.loads(stdout.getvalue())
            res = doc["result"]
            self.assertEqual(doc["command"], "bulk")
            self.assertEqual(res["targets_total"], 2)
            self.assertEqual(res["duplicates_skipped"], 1)
            self.assertEqual(len(res["invalid_lines"]), 1)
            self.assertEqual(res["summary"], {"exposed": 2})
            self.assertEqual(len(res["hosts"]), 2)
            self.assertTrue(all(h["verdict"] == "exposed" for h in res["hosts"]))
            self.assertGreater(res["requests"], 0)
            self.assertGreater(res["bytes_sent"], 0)
            self.assertEqual(res["exit_code"], 1)

            self.assertTrue((out / "summary.json").is_file())
            self.assertTrue((out / "summary.txt").is_file())
            tsv = (out / "summary.tsv").read_text().splitlines()
            self.assertEqual(len(tsv), 3)  # header + two hosts
            self.assertEqual(tsv[0].split("\t")[0], "target")
            hosts = sorted((out / "hosts").glob("*.json"))
            self.assertEqual(len(hosts), 2)
            per_host = json.loads(hosts[0].read_text())
            self.assertEqual(per_host["command"], "probe")
            self.assertTrue(per_host["result"]["quick"])
            self.assertEqual(set(per_host["result"]["uploads"]), {"1mb"})
            self.assertIn("exposed", (out / "summary.txt").read_text())

    def test_static_405_is_inconclusive_not_exposed(self):
        with _server() as srv, tempfile.TemporaryDirectory() as tmp:
            port = srv.server_address[1]
            targets = Path(tmp) / "targets.txt"
            targets.write_text(f"http://127.0.0.1:{port}\n")
            out = Path(tmp) / "out"
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = main(["bulk", str(targets), "--out", str(out), "--format", "json",
                             "--quiet", "--delay", "0", "--host-delay", "0",
                             "--host-timeout", "30", "--quick"])
            self.assertEqual(code, 2, stderr.getvalue())
            doc = json.loads(stdout.getvalue())
            host = doc["result"]["hosts"][0]
            self.assertEqual(host["verdict"], "inconclusive")
            self.assertEqual(doc["result"]["summary"], {"inconclusive": 1})
            self.assertEqual(host["result"]["multipart"]["code"], 405)
            self.assertFalse(host["result"]["php_present"])
            self.assertEqual(host["result"]["php_evidence"], [])
            self.assertEqual(host["result"]["multipart_php_evidence"], [])

    def test_served_php_source_is_not_execution(self):
        with _server(_SourceHandler) as srv:
            doc = probe(Client(f"http://127.0.0.1:{srv.server_address[1]}", delay=0), quick=True)
        res = doc["result"]
        self.assertFalse(res["php_present"])
        self.assertEqual(res["php_evidence"], [])
        self.assertTrue(any("source" in note for note in res["php_notes"]))
        self.assertEqual(res["verdict"]["verdict"], "inconclusive")

    def test_host_timeout_is_enforced(self):
        with _server(_SlowHandler) as srv, tempfile.TemporaryDirectory() as tmp:
            port = srv.server_address[1]
            targets = Path(tmp) / "targets.txt"
            targets.write_text(f"http://127.0.0.1:{port}\n")
            out = Path(tmp) / "out"
            stdout, stderr = io.StringIO(), io.StringIO()
            started = time.monotonic()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = main(["bulk", str(targets), "--out", str(out), "--format", "json",
                             "--quiet", "--delay", "0", "--host-delay", "0",
                             "--host-timeout", "1"])
            elapsed = time.monotonic() - started
            self.assertEqual(code, 2, stderr.getvalue())
            self.assertLess(elapsed, 4)
            doc = json.loads(stdout.getvalue())
            host = doc["result"]["hosts"][0]
            self.assertEqual(host["status"], "timeout")
            self.assertIn("host timeout", host["error"])

    def test_dry_run_sends_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            targets = Path(tmp) / "targets.txt"
            targets.write_text("example.com\nhttps://example.org/app\n")
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = main(["bulk", str(targets), "--dry-run", "--format", "json",
                             "--quiet", "--out", str(Path(tmp) / "out")])
            self.assertEqual(code, 0)
            doc = json.loads(stdout.getvalue())
            self.assertTrue(doc["result"]["dry_run"])
            self.assertEqual(doc["result"]["targets"],
                             ["https://example.com", "https://example.org/app"])
            self.assertFalse((Path(tmp) / "out").exists())


if __name__ == "__main__":
    unittest.main()
