"""Schemas, verdict rules and machine contract for php2shell_scan."""
from __future__ import annotations

SCHEMA = "php2shell.scan/1"

VERDICTS = {
    "mitigated": "multipart POSTs are rejected at the edge; CVE not reachable over HTTP",
    "exposed": "PHP parses attacker multipart pre-auth: CVE surface is reachable",
    "inconclusive": "PHP not confirmed, or nothing answered in a classifiable way",
    "improved": "failure profile improved vs baseline / no worker deaths where baseline had some",
    "changed": "failure profile moved materially vs baseline; inspect flagged cases",
    "unchanged": "profile identical to baseline and no improvement signal",
    "no_signal": "profile flat, no worker deaths in either run; use php -v after the release",
}

EXIT = {"mitigated": 0, "exposed": 1, "inconclusive": 2, "improved": 0, "unchanged": 1,
        "changed": 1, "no_signal": 2}

LIMITS = [
    "Behaves below the app: needs no credentials, CSRF token or route.",
    "Cannot prove a PHP version. Only php -v / dpkg -l | grep php on the origin can.",
    "A flat profile on a patched host is expected; a parser fix need not change status codes.",
    "Worker death (5xx/hang with the static control still 200) is a pre-advisory bug signal only.",
    "Any exploitability percentage is judgement, not measurement, while the advisory is embargoed.",
]


def envelope(cmd: str, target: str, **kw) -> dict:
    doc = {
        "schema": SCHEMA,
        "command": cmd,
        "target": target,
        "generated_at": kw.pop("generated_at", None),
        "result": {},
        "limits": LIMITS,
    }
    doc.update(kw)
    return doc


def verdict_doc(verdict: str, reasons: list[str], **extra) -> dict:
    return {"verdict": verdict, "meaning": VERDICTS.get(verdict, ""),
            "reasons": reasons, "exit_code": EXIT.get(verdict, 2), **extra}


def surface_verdict(php_present: bool, multipart_r: str, multipart_code: int,
                    progress_r: str) -> dict:
    reasons = []
    if not php_present:
        return verdict_doc("inconclusive", ["no PHP-fronted response observed"])
    if multipart_code == 403 and multipart_r == "client":
        return verdict_doc("mitigated", [f"multipart POST -> {multipart_code} (edge block)"])
    if multipart_r in ("ok", "client", "throttle"):
        reasons.append(f"multipart POST parsed by PHP -> {multipart_code} ({multipart_r})")
        if progress_r in ("ok", "client", "throttle"):
            reasons.append("upload-progress field accepted on the same path")
        else:
            reasons.append("upload-progress field not accepted (check ini on the host)")
        return verdict_doc("exposed", reasons)
    if multipart_r in ("hang", "server"):
        return verdict_doc("inconclusive",
                           [f"multipart POST -> {multipart_r}: PHP may be down, retry"])
    return verdict_doc("inconclusive", [f"multipart POST -> {multipart_r}"])


def compare_verdict(old: dict, new: dict, changed_cases: list[str],
                    old_deaths: int, new_deaths: int) -> dict:
    if new_deaths == 0 and old_deaths > 0:
        return verdict_doc("improved", [f"worker deaths {old_deaths} -> 0"])
    if changed_cases:
        return verdict_doc("changed", [f"fail-rate moved >=10pp on {len(changed_cases)} case(s)"],
                           cases=changed_cases)
    if old_deaths > 0 and new_deaths >= old_deaths:
        return verdict_doc("unchanged", [f"same deaths ({new_deaths}), profile flat",
                                         "nothing indicates a patch"])
    return verdict_doc("no_signal", ["flat profile, no deaths in either run"])
