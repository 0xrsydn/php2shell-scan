"""HTTP transport with rate and budget guards. Stdlib only."""
from __future__ import annotations

import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

UA = "php2shell-scan/1.0 (+https://github.com/0xrsydn/php2shell-scan)"

ALIVE = {"ok", "client", "throttle"}
FAIL = {"hang", "server"}


def classify(code: int) -> str:
    if code == 429:
        return "throttle"
    if 200 <= code < 400:
        return "ok"
    if 400 <= code < 500:
        return "client"
    if code >= 500:
        return "server"
    return "other"


class Budget(Exception):
    pass


class Client:
    """One job's view of a target: base URL, guards, and a captured request log."""

    def __init__(self, base: str, *, path: str = "/", timeout: float = 20.0,
                 delay: float = 0.3, rate: float = 0.0, max_requests: int = 0,
                 max_bytes: int = 0, insecure: bool = False, headers: dict | None = None,
                 method: str = "POST", ua: str = UA, verbose: bool = False):
        self.base = base.rstrip("/")
        self.path = path if path.startswith("/") else "/" + path
        self.timeout = timeout
        self.delay = delay
        self.min_gap = 1.0 / rate if rate > 0 else 0.0
        self.max_requests = max_requests
        self.max_bytes = max_bytes
        self.method = method.upper()
        self.headers = headers or {}
        self.ua = ua
        self.verbose = verbose
        self.n = 0
        self.sent_bytes = 0
        self.log: list[dict] = []
        self._last = 0.0
        self.ctx = ssl.create_default_context()
        if insecure:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    # ------------------------------------------------------------------ guards
    def _guard(self):
        if self.max_requests and self.n >= self.max_requests:
            raise Budget(f"request budget exhausted ({self.max_requests})")

    def _pace(self):
        if self.min_gap:
            wait = self.min_gap - (time.time() - self._last)
            if wait > 0:
                time.sleep(wait)
        elif self.delay:
            time.sleep(self.delay)
        self._last = time.time()

    # ------------------------------------------------------------------ request
    def send(self, method: str, path: str, body: bytes | None = None,
             headers: dict | None = None, timeout: float | None = None,
             limit: int = 2048, count: bool = True) -> dict:
        if count:
            self._guard()
            self._pace()
            self.n += 1
            if body:
                self.sent_bytes += len(body)
                if self.max_bytes and self.sent_bytes > self.max_bytes:
                    raise Budget(f"byte budget exhausted ({self.max_bytes})")
        req = urllib.request.Request(self.base + path, data=body, method=method)
        req.add_header("User-Agent", self.ua)
        req.add_header("Accept", "*/*")
        req.add_header("Connection", "close")
        for k, v in {**self.headers, **(headers or {})}.items():
            req.add_header(k, v)
        t0 = time.time()
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout,
                                        context=self.ctx) as r:
                head = r.read(limit)
                code, hdrs = r.status, dict(r.headers)
        except urllib.error.HTTPError as e:
            code, hdrs = e.code, dict(e.headers or {})
            try:
                head = e.read(min(limit, 65536))
            except Exception:
                head = b""
        except (socket.timeout, TimeoutError):
            return self._finish("hang", 0, b"", {}, t0, method, path)
        except urllib.error.URLError as e:
            if isinstance(e.reason, (socket.timeout, TimeoutError)):
                return self._finish("hang", 0, b"", {}, t0, method, path)
            return self._finish("net", 0, str(e.reason).encode(), {}, t0, method, path)
        except ssl.SSLError as e:
            return self._finish("net", 0, str(e).encode(), {}, t0, method, path)
        return self._finish(classify(code), code, head, hdrs, t0, method, path)

    def _finish(self, r, code, head, hdrs, t0, method, path):
        out = {"r": r, "code": code, "head": head, "h": hdrs, "t": round(time.time() - t0, 3),
               "method": method, "path": path}
        if self.verbose:
            self.log.append({"r": r, "code": code, "path": path, "t": out["t"]})
        return out

    def control(self) -> bool:
        """Edge liveness probe: a missing static file still proves nginx answers."""
        r = self.send("GET", "/php2shell-scan-control-404", limit=64)
        return r["code"] in (200, 301, 302, 403, 404)


def url_ok(u: str) -> str:
    p = urllib.parse.urlsplit(u)
    if p.scheme not in ("http", "https") or not p.netloc:
        raise ValueError(f"not an http(s) URL: {u}")
    return u
