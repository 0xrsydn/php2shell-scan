"""Bulk target scanning: native version of the probe-websites.sh wrapper (issue #1)."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

from . import report

MAX_WORKERS = 32


class BulkError(Exception):
    pass


@dataclass
class TargetList:
    label: str
    targets: list[str]
    invalid: list[dict]
    duplicates: int


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_target(raw: str) -> str:
    """Turn a host-list line into a canonical base URL. Bare hosts default to https."""
    value = raw.strip()
    if not value:
        raise ValueError("empty target")
    if "://" not in value:
        value = "https://" + value
    try:
        parts = urlsplit(value)
    except ValueError as exc:
        raise ValueError(f"invalid URL: {exc}") from exc
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"unsupported scheme {parts.scheme!r}")
    if not parts.netloc:
        raise ValueError("missing host")
    if "//" in parts.netloc or any(ch.isspace() for ch in parts.netloc):
        raise ValueError("invalid host")
    if parts.query:
        raise ValueError("query strings are not supported")
    if parts.fragment:
        raise ValueError("fragments are not supported")
    try:
        host = parts.hostname
        parts.port  # raises ValueError on a malformed port
    except ValueError as exc:
        raise ValueError(f"invalid host or port: {exc}") from exc
    if not host:
        raise ValueError("missing host")
    if "*" in host:
        raise ValueError("wildcards are not supported")
    return urlunsplit((scheme, parts.netloc, parts.path.rstrip("/"), "", ""))


def load_targets(path: str) -> TargetList:
    """Read one target per line. Blank lines and ``#`` comments are ignored."""
    if path == "-":
        label = "<stdin>"
        try:
            text = sys.stdin.read()
        except OSError as exc:
            raise BulkError(f"cannot read stdin: {exc}") from exc
    else:
        label = path
        try:
            with open(path, encoding="utf-8-sig") as f:
                text = f.read()
        except OSError as exc:
            raise BulkError(f"cannot read target list {path}: {exc}") from exc

    targets: list[str] = []
    invalid: list[dict] = []
    seen: set[str] = set()
    duplicates = 0
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            target = normalize_target(line)
        except ValueError as exc:
            invalid.append({"line": lineno, "value": line, "error": str(exc)})
            continue
        if target in seen:
            duplicates += 1
            continue
        seen.add(target)
        targets.append(target)
    return TargetList(label=label, targets=targets, invalid=invalid, duplicates=duplicates)


def _slug(target: str) -> str:
    text = re.sub(r"^[a-z]+://", "", target, flags=re.IGNORECASE)
    text = re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("._-")
    return (text or "target")[:80]


def _probe_argv(a, target: str) -> list[str]:
    """Build the child command. A child process gives us a hard, killable timeout."""
    argv = [
        sys.executable, "-m", "php2shell_scan", "probe", target,
        "--path", a.path, "--method", a.method,
        "--delay", str(a.delay), "--rate", str(a.rate),
        "--max-requests", str(a.max_requests), "--max-bytes", str(a.max_bytes),
        "--timeout", str(a.timeout), "--format", "json", "--quiet",
    ]
    if a.quick:
        argv.append("--quick")
    if a.insecure:
        argv.append("--insecure")
    if a.ua:
        argv += ["--ua", a.ua]
    if a.cookie:
        argv += ["--cookie", a.cookie]
    for header in a.header:
        argv += ["--header", header]
    return argv


def _as_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _run_one(a, target: str) -> tuple[dict, dict | None]:
    argv = _probe_argv(a, target)
    started = time.monotonic()
    timeout = a.host_timeout if a.host_timeout > 0 else None
    try:
        proc = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                              text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        elapsed = round(time.monotonic() - started, 2)
        detail = _as_text(exc.stderr).strip()
        error = f"host timeout after {a.host_timeout:g}s"
        if detail:
            error += f": {detail[-2000:]}"
        rec = {"target": target, "status": "timeout", "verdict": None, "exit_code": None,
               "elapsed_s": elapsed, "error": error}
        return rec, None
    except OSError as exc:
        elapsed = round(time.monotonic() - started, 2)
        return {"target": target, "status": "error", "verdict": None, "exit_code": None,
                "elapsed_s": elapsed, "error": f"cannot start scanner: {exc}"}, None

    elapsed = round(time.monotonic() - started, 2)
    rec = {"target": target, "status": "error", "verdict": None,
           "exit_code": proc.returncode, "elapsed_s": elapsed, "error": None}
    doc = None
    if proc.stdout.strip():
        try:
            doc = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            rec["error"] = f"invalid scanner JSON: {exc}"
    if isinstance(doc, dict):
        res = doc.get("result")
        if isinstance(res, dict):
            rec["result"] = res
            rec["requests"] = res.get("requests")
            rec["bytes_sent"] = res.get("bytes_sent")
            verdict = res.get("verdict")
            if isinstance(verdict, dict) and isinstance(verdict.get("verdict"), str):
                rec["verdict"] = verdict["verdict"]
                rec["exit_code"] = verdict.get("exit_code", proc.returncode)
                rec["status"] = "ok"
            else:
                rec["error"] = rec["error"] or "scanner returned no verdict"
        else:
            rec["error"] = rec["error"] or "scanner returned no result"
    elif not rec["error"]:
        rec["error"] = f"scanner returned no JSON (exit {proc.returncode})"
    if proc.returncode < 0:
        rec["status"] = "error"
        rec["error"] = f"scanner killed by signal {-proc.returncode}"
    stderr = (proc.stderr or "").strip()
    if stderr:
        rec["stderr"] = stderr[-4000:]
    return rec, doc if isinstance(doc, dict) else None


def aggregate_exit(records: list[dict]) -> int:
    """1 if any host is exposed/changed, else 2 if any host is unproven, else 0."""
    codes = [r.get("exit_code") for r in records]
    if any(code == 1 for code in codes):
        return 1
    if any(code != 0 for code in codes) or any(r.get("status") != "ok" for r in records):
        return 2
    return 0


def _counts(records: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for rec in records:
        key = rec.get("verdict") or rec.get("status") or "unknown"
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


def _sum(records: list[dict], key: str) -> int:
    return sum(r.get(key) or 0 for r in records if isinstance(r.get(key), (int, float)))


def _default_out_dir() -> str:
    base = os.path.join("php2shell-results", "scan-" + datetime.now(timezone.utc)
                        .strftime("%Y%m%dT%H%M%SZ"))
    out, suffix = base, 1
    while os.path.exists(out):
        suffix += 1
        out = f"{base}-{suffix}"
    return out


def _run_all(a, targets: list[str]) -> tuple[list[dict], list[dict | None]]:
    records: list[dict] = [{} for _ in targets]
    docs: list[dict | None] = [None for _ in targets]
    done = 0
    lock = threading.Lock()

    def one(index: int):
        nonlocal done
        try:
            rec, doc = _run_one(a, targets[index])
        except Exception as exc:  # one bad target must not abort the list
            rec, doc = {
                "target": targets[index], "status": "error", "verdict": None,
                "exit_code": None, "elapsed_s": 0.0,
                "error": f"bulk worker failed: {exc}",
            }, None
        records[index], docs[index] = rec, doc
        with lock:
            done += 1
            more = done < len(targets)
            if not a.quiet:
                label = rec.get("verdict") or rec.get("status")
                print(f"[{done}/{len(targets)}] {label:12} {targets[index]} "
                      f"({rec['elapsed_s']:.1f}s)", file=sys.stderr, flush=True)
        if more and a.workers > 1 and a.host_delay:
            time.sleep(a.host_delay)

    if a.workers == 1:
        for index in range(len(targets)):
            if index and a.host_delay:
                time.sleep(a.host_delay)
            one(index)
    else:
        with ThreadPoolExecutor(max_workers=a.workers) as pool:
            futures = {pool.submit(one, index): index for index in range(len(targets))}
            for future in as_completed(futures):
                index = futures[future]
                exc = future.exception()
                if exc is not None:
                    records[index] = {
                        "target": targets[index], "status": "error", "verdict": None,
                        "exit_code": None, "elapsed_s": 0.0,
                        "error": f"bulk worker failed: {exc}",
                    }
    return records, docs


def _clean(value) -> str:
    return str(value if value is not None else "").replace("\t", " ").replace("\n", " ")


def _write_outputs(out_dir: str, doc: dict, records: list[dict],
                   docs: list[dict | None], targets: list[str]) -> None:
    os.makedirs(out_dir, exist_ok=True)
    host_dir = os.path.join(out_dir, "hosts")
    os.makedirs(host_dir, exist_ok=True)
    for index, (target, rec, host_doc) in enumerate(zip(targets, records, docs), 1):
        path = os.path.join(host_dir, f"{index:04d}-{_slug(target)}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(host_doc if host_doc is not None else rec, f, indent=1)
    with open(os.path.join(out_dir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1)
    columns = ("target", "status", "verdict", "exit_code", "requests", "bytes_sent",
               "php_worker_deaths", "elapsed_s", "error")
    with open(os.path.join(out_dir, "summary.tsv"), "w", encoding="utf-8") as f:
        f.write("\t".join(columns) + "\n")
        for rec in records:
            f.write("\t".join(_clean(rec.get(column)) for column in columns) + "\n")
    with open(os.path.join(out_dir, "summary.txt"), "w", encoding="utf-8") as f:
        f.write(text_summary(doc) + "\n")


def scan(a) -> dict:
    if a.workers < 1 or a.workers > MAX_WORKERS:
        raise BulkError(f"--workers must be between 1 and {MAX_WORKERS}")
    if a.host_timeout < 0:
        raise BulkError("--host-timeout must be >= 0 (0 disables the timeout)")
    if a.host_delay < 0:
        raise BulkError("--host-delay must be >= 0")

    target_list = load_targets(a.target)
    for bad in target_list.invalid:
        print(f"warning: {target_list.label}: line {bad['line']}: {bad['value']!r}: "
              f"{bad['error']}", file=sys.stderr)
    if not target_list.targets:
        raise BulkError(f"no valid targets in {target_list.label}")

    doc = report.envelope("bulk", target_list.label, generated_at=now())
    doc["input"] = target_list.label
    result = doc["result"]
    result["targets_total"] = len(target_list.targets)
    result["duplicates_skipped"] = target_list.duplicates
    result["invalid_lines"] = target_list.invalid

    if a.dry_run:
        result.update({"dry_run": True, "targets": target_list.targets, "exit_code": 0})
        return doc

    out_dir = None if a.out == "-" else os.path.expanduser(a.out or _default_out_dir())
    started = time.monotonic()
    records, docs = _run_all(a, target_list.targets)
    if out_dir:
        result["results_dir"] = out_dir
    result.update({
        "summary": _counts(records),
        "requests": _sum(records, "requests"),
        "bytes_sent": _sum(records, "bytes_sent"),
        "php_worker_deaths": _sum(records, "php_worker_deaths"),
        "elapsed_s": round(time.monotonic() - started, 2),
        "hosts": records,
        "exit_code": aggregate_exit(records),
    })
    if out_dir:
        try:
            _write_outputs(out_dir, doc, records, docs, target_list.targets)
        except OSError as exc:
            result["save_error"] = str(exc)
            print(f"warning: could not write results to {out_dir}: {exc}", file=sys.stderr)
        else:
            print(f"Results: {out_dir}", file=sys.stderr, flush=True)
    return doc


def text_summary(doc: dict) -> str:
    res = doc.get("result", {})
    lines = [f"bulk {doc.get('target')}  [{doc.get('generated_at')}]"]
    if res.get("dry_run"):
        lines.append(f"  targets: {res.get('targets_total')} (dry run; no requests sent)")
        for target in res.get("targets") or []:
            lines.append(f"    {target}")
        return "\n".join(lines)
    lines.append(f"  targets: {res.get('targets_total')} "
                 f"({res.get('duplicates_skipped', 0)} duplicates skipped, "
                 f"{len(res.get('invalid_lines') or [])} invalid)")
    for key, value in (res.get("summary") or {}).items():
        lines.append(f"  {key}: {value}")
    for key in ("requests", "bytes_sent", "elapsed_s"):
        if key in res:
            lines.append(f"  {key}: {res[key]}")
    if res.get("results_dir"):
        lines.append(f"  results: {res['results_dir']}")
    lines.append("  hosts:")
    for rec in res.get("hosts") or []:
        label = rec.get("verdict") or rec.get("status") or "error"
        exit_code = rec.get("exit_code")
        exit_text = "-" if exit_code is None else exit_code
        error = rec.get("error")
        suffix = f" — {error[:200]}" if error else ""
        lines.append(f"    {label:12} {rec.get('target')} "
                     f"(exit {exit_text}, {rec.get('elapsed_s', 0)}s){suffix}")
    return "\n".join(lines)
