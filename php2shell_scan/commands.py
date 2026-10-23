"""Commands: probe, baseline, stress, burst, compare, verdict. All return report docs."""
from __future__ import annotations

import json
import re
import threading
import time
from datetime import datetime, timezone

from . import corpus, report
from .transport import ALIVE, FAIL, Budget


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


PHP_COOKIE_MARKERS = ("phpsessid", "laravel_session", "ci_session", "wordpress_",
                      "wp-settings-", "joomla_", "yii_", "symfony", "phpbb3_", "kohana_session")


def _php_evidence(r: dict) -> list[str]:
    """Headers/cookies that only a PHP-backed stack normally emits."""
    h = {k.lower(): v for k, v in (r.get("h") or {}).items()}
    evidence = []
    powered = h.get("x-powered-by", "")
    if "php" in powered.lower():
        evidence.append(f"x-powered-by: {powered}")
    server = h.get("server", "")
    if "php" in server.lower():
        evidence.append(f"server: {server}")
    cookies = h.get("set-cookie", "")
    for marker in PHP_COOKIE_MARKERS:
        if marker in cookies.lower():
            evidence.append(f"cookie: {marker}")
    location = h.get("location", "")
    if ".php" in location.lower():
        evidence.append(f"redirect: {location}")
    return evidence


def _merge_evidence(evidence: list[str], extra: list[str]) -> None:
    for item in extra:
        if item not in evidence:
            evidence.append(item)


def probe(cl, *, quick: bool = False) -> dict:
    doc = report.envelope("probe", cl.base, generated_at=now(), result={})
    res = doc["result"]
    res["quick"] = quick
    r = cl.send("GET", "/")
    res["root"] = {"status": r["r"], "code": r["code"]}
    h = {k.lower(): v for k, v in (r.get("h") or {}).items()}
    res["server_headers"] = {k: h[k] for k in ("server", "x-powered-by", "via") if k in h}
    res["server_hint"] = _server_hint(h)
    res["php_evidence"] = []
    res["php_notes"] = []
    _merge_evidence(res["php_evidence"], _php_evidence(r))

    # /index.php is the cheapest direct test that a PHP script executes. A 405 on POST /
    # does not prove PHP: static nginx returns the same code.
    idx = cl.send("GET", "/index.php", limit=8192)
    res["index_php"] = {"status": idx["r"], "code": idx["code"]}
    _merge_evidence(res["php_evidence"], _php_evidence(idx))
    if idx["code"] == 200:
        head = (idx["head"] or b"").lower()
        if b"<?php" in head or b"<?=" in head:
            res["php_notes"].append("GET /index.php returned 200 with PHP source; PHP is not executing")
        else:
            res["php_evidence"].append("GET /index.php -> 200")
    elif idx["r"] == "server":
        res["php_evidence"].append(f"GET /index.php -> {idx['code']} (PHP error)")

    lg = cl.send("GET", "/login")
    _merge_evidence(res["php_evidence"], _php_evidence(lg))
    if lg["code"] == 200:
        res["fingerprints"] = {"login_page": 200}
    else:
        res["fingerprints"] = {}
    res["php_present"] = bool(res["php_evidence"])

    if res["php_present"]:
        lw = cl.send("GET", "/vendor/livewire/livewire.min.js", limit=400_000)
        _merge_evidence(res["php_evidence"], _php_evidence(lw))
        m = re.search(rb'version:"([0-9]+\.[0-9]+\.[0-9]+)"', lw["head"] or b"")
        if m:
            res["fingerprints"]["livewire"] = m.group(1).decode()
    res["php_min_guess"] = 8.1 if res["fingerprints"].get("livewire", "").startswith("3.") else None

    _, hdr, body = corpus.case("progress")
    mp = cl.send(cl.method, cl.path, body, hdr)
    res["multipart"] = {"status": mp["r"], "code": mp["code"]}
    res["upload_progress"] = {"status": mp["r"]}  # same request carried the field
    res["multipart_php_evidence"] = _php_evidence(mp)
    _merge_evidence(res["php_evidence"], res["multipart_php_evidence"])

    res["uploads"] = {}
    for mb in ((1,) if quick else (1, 8, 32)):
        _, hh, bb = corpus.build("big", [corpus.part("f", b"\0" * (mb << 20), filename="z.bin")])
        rr = cl.send(cl.method, cl.path, bb, hh, timeout=max(cl.timeout, 60))
        upload_evidence = _php_evidence(rr)
        _merge_evidence(res["php_evidence"], upload_evidence)
        _merge_evidence(res["multipart_php_evidence"], upload_evidence)
        res["uploads"][f"{mb}mb"] = rr["code"] if rr["r"] != "hang" else "hang"
        if rr["r"] in FAIL and not cl.control():
            res["uploads"][f"{mb}mb"] = "php_dead"
            break

    res["php_present"] = bool(res["php_evidence"])
    res["verdict"] = report.surface_verdict(
        res["php_present"], res["multipart"]["status"], res["multipart"]["code"],
        res["upload_progress"]["status"],
        multipart_evidence=bool(res["multipart_php_evidence"]))
    res["requests"] = cl.n
    res["bytes_sent"] = cl.sent_bytes
    return doc


def _server_hint(h: dict) -> list[str]:
    hints = []
    srv = (h.get("server") or "").lower()
    if "nginx" in srv:
        hints.append("nginx front")
    if "apache" in srv:
        hints.append("apache front")
    if "cdn" in srv or "cloudflare" in srv:
        hints.append("possible CDN/WAF")
    if "x-powered-by" not in h:
        hints.append("x-powered-by stripped")
    if "via" in h:
        hints.append("proxy via header")
    return hints


def by_name(name: str):
    if name == "many-parts":
        return corpus.many_parts()
    return corpus.case(name)


def _record(prof, deaths, cl, name, r):
    e = prof.setdefault(name, {"ok": 0, "client": 0, "throttle": 0, "server": 0,
                               "hang": 0, "net": 0, "other": 0, "codes": {}, "t": []})
    e[r["r"]] += 1
    e["codes"][str(r["code"])] = e["codes"].get(str(r["code"]), 0) + 1
    e["t"].append(r["t"])
    if r["r"] in FAIL:
        alive = cl.control()
        e["edge_alive"] = alive
        if r["r"] == "hang" and alive:
            deaths += 1
    return deaths, e


def run_corpus(cl, *, rounds: int, per_case: int, heavy: bool, path: str | None = None,
               rand_n: int = 0, progress_cb=None) -> dict:
    """Fixed cases keep the profile comparable across runs; rand adds heap-shaping jitter."""
    cases = corpus.corpus(heavy)
    prof: dict[str, dict] = {}
    deaths = 0
    total = 0
    for _ in range(rounds):
        for name, hdr, body in cases:
            for _ in range(per_case):
                total += 1
                r = cl.send(cl.method, path or cl.path, body, hdr)
                deaths, e = _record(prof, deaths, cl, name, r)
                if progress_cb:
                    progress_cb(name, e, total)
        for _ in range(rand_n):
            name, hdr, body = corpus.rand()
            total += 1
            r = cl.send(cl.method, path or cl.path, body, hdr)
            deaths, e = _record(prof, deaths, cl, "rand", r)
    return {"target": cl.base, "at": now(), "rounds": rounds, "per_case": per_case,
            "heavy": heavy, "php_worker_deaths": deaths, "by_case": prof,
            "totals": {k: sum(e[k] for e in prof.values()) for k in
                       ("ok", "client", "throttle", "server", "hang", "net", "other")},
            "requests": cl.n, "bytes_sent": cl.sent_bytes}


def baseline(cl, *, rounds: int, per_case: int, heavy: bool, rand_n: int = 6) -> dict:
    doc = report.envelope("baseline", cl.base, generated_at=now())
    doc["result"] = run_corpus(cl, rounds=rounds, per_case=per_case, heavy=heavy, rand_n=rand_n)
    return doc


def stress(cl, *, cases: list[str] | None, per_case: int, heavy: bool) -> dict:
    doc = report.envelope("stress", cl.base, generated_at=now())
    if cases:
        prof, deaths = {}, 0
        for name in cases:
            _, hdr, body = by_name(name)
            for _ in range(per_case):
                r = cl.send(cl.method, cl.path, body, hdr)
                deaths, _ = _record(prof, deaths, cl, name, r)
        doc["result"] = {"target": cl.base, "at": now(), "per_case": per_case, "heavy": heavy,
                         "php_worker_deaths": deaths, "by_case": prof,
                         "totals": {k: sum(e[k] for e in prof.values()) for k in
                                    ("ok", "client", "throttle", "server", "hang", "net", "other")},
                         "requests": cl.n, "bytes_sent": cl.sent_bytes}
        return doc
    doc["result"] = run_corpus(cl, rounds=1, per_case=per_case, heavy=heavy, rand_n=0)
    return doc


def burst(cl, *, n: int, conc: int, size: int) -> dict:
    doc = report.envelope("burst", cl.base, generated_at=now())
    res = {"n": n, "conc": conc, "part_bytes": size, "events": [], "deaths": 0}
    lock = threading.Lock()

    def worker(i: int):
        _, hdr, body = corpus.build("burst", [corpus.part(corpus.PROGRESS, f"b{i}"),
                                              corpus.part("f", b"\0" * size, filename=f"{i}.bin")])
        try:
            r = cl.send(cl.method, cl.path, body, hdr, timeout=max(cl.timeout, 90))
        except Budget as exc:
            with lock:
                res["events"].append({"i": i, "r": "budget", "t": 0})
            return
        with lock:
            res["events"].append({"i": i, "r": r["r"], "code": r["code"], "t": r["t"]})
            if r["r"] in FAIL:
                alive = cl.control()
                res["events"][-1]["edge_alive"] = alive
                if not alive:
                    res["deaths"] += 1

    th: list[threading.Thread] = []
    for i in range(n):
        t = threading.Thread(target=worker, args=(i,))
        t.start()
        th.append(t)
        while sum(1 for x in th if x.is_alive()) >= conc:
            time.sleep(0.03)
        if cl.delay:
            time.sleep(cl.delay)
    for t in th:
        t.join()
    res["codes"] = {}
    for e in res["events"]:
        res["codes"][str(e["code"])] = res["codes"].get(str(e["code"]), 0) + 1
    res["fail"] = sum(1 for e in res["events"] if e["r"] in FAIL)
    res["worst_seconds"] = max((e.get("t", 0) for e in res["events"]), default=0)
    res["verdict"] = ("workers_died" if res["deaths"] else
                      "degraded" if res["fail"] else "healthy")
    doc["result"] = res
    return doc


def _fail_rate(e: dict) -> float:
    tot = sum(e.get(k, 0) for k in ("ok", "client", "throttle", "server", "hang", "net", "other")) or 1
    return 100.0 * sum(e.get(k, 0) for k in FAIL) / tot


def compare(old: dict, new: dict, threshold: float = 10.0) -> dict:
    doc = report.envelope("compare", new["target"], generated_at=now())
    rows, flagged = [], []
    for name in sorted(set(old["by_case"]) | set(new["by_case"])):
        of, nf = _fail_rate(old["by_case"].get(name, {})), _fail_rate(new["by_case"].get(name, {}))
        delta = nf - of
        if abs(delta) >= threshold:
            flagged.append({"case": name, "delta_pp": round(delta, 1)})
        rows.append({"case": name, "before_pp": round(of, 1), "after_pp": round(nf, 1),
                     "flagged": abs(delta) >= threshold})
    v = report.compare_verdict(old, new, [f["case"] for f in flagged],
                               old["php_worker_deaths"], new["php_worker_deaths"])
    doc["result"] = {"before_at": old["at"], "after_at": new["at"],
                     "before_deaths": old["php_worker_deaths"],
                     "after_deaths": new["php_worker_deaths"],
                     "cases": rows, "verdict": v}
    return doc


def verdict(cl, baseline_doc: dict, *, rounds: int, per_case: int, heavy: bool,
            rand_n: int = 6) -> dict:
    doc = report.envelope("verdict", cl.base, generated_at=now())
    r = cl.send("GET", "/")
    live = {"code": r["code"], "status": r["r"], "edge_alive": cl.control()}
    new = run_corpus(cl, rounds=rounds, per_case=per_case, heavy=heavy, rand_n=rand_n)
    cmp_doc = compare(baseline_doc, new)
    doc["result"] = {"live": live, "comparison": cmp_doc["result"],
                     "baseline_at": baseline_doc["at"],
                     "verdict": cmp_doc["result"]["verdict"]}
    return doc
