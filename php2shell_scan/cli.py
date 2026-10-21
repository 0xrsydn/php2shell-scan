"""Command line entry point."""
from __future__ import annotations

import argparse
import json
import sys

from . import commands, report
from .transport import UA, Budget, Client, url_ok

COMMANDS = ("probe", "baseline", "stress", "burst", "compare", "verdict")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="php2shell-scan",
        description="Reachability + change detector for CVE-2026-109618 / CVE-2026-109619 "
                    "(php2shell). Read-only unless --path writes.")
    p.add_argument("cmd", choices=COMMANDS)
    p.add_argument("target", help="base URL, e.g. https://host/")
    p.add_argument("baseline", nargs="?", help="baseline JSON file (compare/verdict)")

    g = p.add_argument_group("request shaping")
    g.add_argument("--path", default="/", help="POST path (default /, cheapest parser hit)")
    g.add_argument("--method", default="POST")
    g.add_argument("--header", action="append", default=[], metavar="K:V",
                   help="extra header, repeatable (auth, X-Forwarded-For, ...)")
    g.add_argument("--cookie", help="Cookie header value")
    g.add_argument("--ua", default=None, help="User-Agent override")
    g.add_argument("--insecure", action="store_true", help="skip TLS verification")

    g = p.add_argument_group("politeness guards")
    g.add_argument("--delay", type=float, default=0.3, help="seconds between requests (default .3)")
    g.add_argument("--rate", type=float, default=0.0, help="requests/second cap (overrides delay)")
    g.add_argument("--max-requests", type=int, default=0, help="hard request budget")
    g.add_argument("--max-bytes", type=int, default=0, help="hard upload budget in bytes")
    g.add_argument("--timeout", type=float, default=20.0)

    g = p.add_argument_group("scan shaping")
    g.add_argument("--rounds", type=int, default=1)
    g.add_argument("--per-case", type=int, default=1)
    g.add_argument("--case", action="append", help="restrict stress to named case(s)")
    g.add_argument("--heavy", action="store_true", help="add 256KB-part and 1100-part cases")
    g.add_argument("--rand", type=int, default=6, help="randomised heap-shaping bodies per round")
    g.add_argument("--n", type=int, default=12, help="burst: requests")
    g.add_argument("--conc", type=int, default=4, help="burst: concurrency")
    g.add_argument("--size", type=int, default=2 << 20, help="burst: part size in bytes")
    g.add_argument("--threshold", type=float, default=10.0,
                   help="compare: fail-rate delta in pp that counts as change")

    g = p.add_argument_group("output")
    g.add_argument("--format", choices=["text", "json", "both"], default="text")
    g.add_argument("--save", metavar="FILE", help="write the JSON document here")
    g.add_argument("--quiet", action="store_true")
    return p


def _headers(a) -> dict:
    h = {}
    for item in a.header:
        k, _, v = item.partition(":")
        h[k.strip()] = v.strip()
    if a.cookie:
        h["Cookie"] = a.cookie
    return h


def _text(doc: dict) -> str:
    res = doc.get("result", {})
    v = res.get("verdict")
    lines = [f"{doc['command']} {doc['target']}  [{doc['generated_at']}]"]
    if isinstance(v, dict):
        lines.append(f"VERDICT: {v['verdict']} — {v['meaning']}")
        for why in v.get("reasons", []):
            lines.append(f"  - {why}")
    for k in ("server_headers", "server_hint", "fingerprints", "php_min_guess", "multipart",
              "upload_progress", "uploads", "php_worker_deaths", "totals", "requests",
              "bytes_sent", "fail", "codes", "worst_seconds", "n", "conc"):
        if k in res:
            lines.append(f"  {k}: {json.dumps(res[k])}")
    if res.get("cases"):
        for row in res["cases"]:
            mark = "!" if row["flagged"] else " "
            lines.append(f" {mark} {row['case']:26} {row['before_pp']:5.1f}% -> {row['after_pp']:5.1f}%")
    if res.get("by_case"):
        for name, e in sorted(res["by_case"].items()):
            lines.append(f"  {name:26} {json.dumps(e['codes'])}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    try:
        url_ok(a.target)
    except ValueError as e:
        print(e, file=sys.stderr)
        return 2
    cl = Client(a.target, path=a.path, timeout=a.timeout, delay=a.delay, rate=a.rate,
                max_requests=a.max_requests, max_bytes=a.max_bytes, insecure=a.insecure,
                headers=_headers(a), method=a.method, ua=a.ua or UA)

    try:
        if a.cmd == "probe":
            doc = commands.probe(cl)
        elif a.cmd == "baseline":
            doc = commands.baseline(cl, rounds=a.rounds, per_case=a.per_case, heavy=a.heavy,
                                     rand_n=a.rand)
        elif a.cmd == "stress":
            doc = commands.stress(cl, cases=a.case, per_case=a.per_case, heavy=a.heavy)
        elif a.cmd == "burst":
            doc = commands.burst(cl, n=a.n, conc=a.conc, size=a.size)
        else:
            if not a.baseline:
                print(f"{a.cmd} needs a baseline JSON file", file=sys.stderr)
                return 2
            with open(a.baseline) as f:
                base = json.load(f)
            if a.cmd == "compare":
                new = commands.run_corpus(cl, rounds=a.rounds, per_case=a.per_case,
                                           heavy=a.heavy, rand_n=a.rand)
                doc = commands.compare(base["result"] if "result" in base else base, new,
                                       threshold=a.threshold)
            else:
                doc = commands.verdict(cl, base["result"] if "result" in base else base,
                                       rounds=a.rounds, per_case=a.per_case, heavy=a.heavy,
                                       rand_n=a.rand)
    except Budget as exc:
        print(f"stopped: {exc}", file=sys.stderr)
        return 2

    if a.save:
        with open(a.save, "w") as f:
            json.dump(doc, f, indent=1)
    res = doc.get("result", {})
    v = res.get("verdict")
    code = v["exit_code"] if isinstance(v, dict) else 0
    if a.format in ("json", "both"):
        print(json.dumps(doc, indent=1))
    if a.format in ("text", "both") and not a.quiet:
        print(_text(doc), file=sys.stderr if a.format == "both" else sys.stdout)
    return code


if __name__ == "__main__":
    sys.exit(main())
