---
name: php2shell-scan
description: Assess whether a PHP site is exposed to the php2shell RCEs (CVE-2026-109618 / CVE-2026-109619) and whether it has been patched since a stored baseline. Use when asked if a site is vulnerable to php2shell, to "check for the PHP RCE", to verify a PHP patch landed, or to scan a PHP host without credentials.
---

# php2shell-scan

`php2shell-scan` decides two things about a PHP host: **is the vulnerable code path reachable**
(pre-auth multipart / upload-progress, below the application), and **has anything changed since the
baseline** you recorded earlier. It does not need credentials, CSRF tokens or app knowledge.

Runs on the Python stdlib. Install: `pipx install git+https://github.com/0xrsydn/php2shell-scan` or
`python3 -m php2shell_scan` from a clone.

## Order of operations

```bash
php2shell-scan probe   https://host/                       # always first; cheap, 5 requests + uploads
php2shell-scan baseline https://host/ --save host-pre.json # once, before the patch lands
php2shell-scan verdict https://host/ host-pre.json         # after the patch: did it move?
```

`probe` decides reachability. `verdict` diffs a live run against the baseline and returns one of
`improved` / `changed` / `unchanged` / `no_signal`. `compare` does the same between two saved JSON
files and never touches the network when given `--against`.

## Reading the result

| Verdict | Meaning | Agent action |
|---|---|---|
| `mitigated` | multipart rejected at the edge (`403`) | report as mitigated, not fixed |
| `exposed` | PHP parses attacker multipart pre-auth | report vulnerable, escalate to the PHP owner |
| `inconclusive` | no PHP confirmed, or PHP down under load | retry once, then report the outage too |
| `improved` | no worker deaths where the baseline had some | likely patched — confirm with `php -v` |
| `changed` | fail profile moved ≥10 pp | inspect flagged cases before concluding |
| `unchanged` | identical to baseline, deaths persist | still vulnerable |
| `no_signal` | flat profile, no deaths either run | not proof of safety; use `php -v` |

Exit codes match: `0` mitigated/improved, `1` exposed/unchanged/changed, `2` inconclusive/no_signal.

## Ground rules

- `--format json` puts one object on stdout with `schema: "php2shell.scan/1"`; put human text behind
  `--format both` so stdout stays parseable.
- Politeness defaults are safe for production (`--delay 0.3`, `--per-case 1`, no `--heavy`). Add
  `--max-requests` / `--max-bytes` before `--heavy` or `--conc 6+` on a government/pharma host.
- `POST /` is the default path because it usually 405s — a parser hit with no DB write. Use
  `--path /some/form` with `--method POST` only when you want the full app stack (it writes rows).
- Throttled endpoints surface as `429` and are classified `throttle` (alive, never a vulnerability
  signal).
- Worker death shows as `hang`/`5xx` **with the static control still answering**; FPM respawns
  children, so read `php_worker_deaths`, never the HTTP code alone.
- Never claim a version from this tool. Livewire ≥3 only bounds PHP at ≥8.1. Version truth is
  `php -v` / `dpkg -l | grep php` on the origin.

## Hard limits to state in reports

- Cannot prove a patch. A parser fix need not change any status code; `no_signal` on a patched host
  is expected.
- The bug lives in PHP core (`rfc1867.c` / upload-progress bookkeeping), so app stack, auth design,
  CSRF and `APP_DEBUG` are irrelevant.
- If `file_uploads=Off` or `session.upload_progress.enabled=Off` on the host, `exposed` can still be
  a false positive — only the ini values settle it.
- Exploitability percentages are judgement, not measurement, until an advisory/PoC is public.

## Lab

`lab/` reproduces the request path (nginx → php-fpm, uploads on, progress on) for detonating an
untrusted sample before pointing it at the real host: `lab/detonate.sh <sample>`. See `lab/README.md`.

## References

- CVE-2026-109618, CVE-2026-109619 — PHP core RCE, CVSS v4.0 9.2, disclosed 2026-10-20, fixes
  2026-10-21 14:00 UTC.
- `php.net/archive/2026.php`, `sansec.io/research/php2shell`, `watchtowr.com` FAQ.
