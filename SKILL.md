---
name: php2shell-scan
description: Assess whether a PHP site is exposed to the php2shell RCEs (CVE-2026-109618 / CVE-2026-109619) and whether it has been patched since a stored baseline. Use when asked if a site is vulnerable to php2shell, to "check for the PHP RCE", to verify a PHP patch landed, or to scan one or many PHP hosts without credentials.
---

# php2shell-scan

`php2shell-scan` decides two things about a PHP host: **is the vulnerable code path reachable**
(pre-auth multipart / upload-progress, below the application), and **has anything changed since the
baseline** you recorded earlier. It does not need credentials, CSRF tokens or app knowledge.

Runs on the Python stdlib. Install: `pipx install git+https://github.com/0xrsydn/php2shell-scan` or
`python3 -m php2shell_scan` from a clone.

## Order of operations

```bash
php2shell-scan probe   https://host/                       # always first; cheap, ~8 requests + uploads
php2shell-scan baseline https://host/ --save host-pre.json # once, before the patch lands
php2shell-scan verdict https://host/ host-pre.json         # after the patch: did it move?
```

`probe` decides reachability. `verdict` diffs a live run against the baseline and returns one of
`improved` / `changed` / `unchanged` / `no_signal`. `compare` does the same between two saved JSON
files and never touches the network when given `--against`.

## Many hosts

`bulk` scans a target list without a shell wrapper:

```bash
php2shell-scan bulk targets.txt --out results/ --format json
cat targets.txt | php2shell-scan bulk - --workers 4 --host-timeout 60
php2shell-scan bulk targets.txt --dry-run
```

One target per line; blank lines and `#` comments are ignored, bare hosts default to `https://`,
duplicates are removed, and invalid lines are reported and skipped. Each target is a separate
`probe` child process with a hard `--host-timeout` (default 60 s), so a wedged host cannot stall the
list. Targets run sequentially unless `--workers` is raised; `--host-delay` defaults to 1 s per
worker. Probe request options (`--path`, `--header`, `--cookie`, `--ua`, `--insecure`, `--delay`,
`--max-requests`, `--max-bytes`) apply to every target. Add `--quick` for large lists: it skips the
8 MB/32 MB upload probes (about 41 MB per host) and keeps the multipart and 1 MB probes.

`--out` (default `php2shell-results/scan-<UTC>/`, `-` disables files) writes `summary.tsv`,
`summary.json`, `summary.txt`, and one full `probe` document per host under `hosts/`. Bulk exit is
`1` if any target reports `exposed`/`changed`, else `2` if any target is inconclusive or failed,
else `0`. Read the per-host verdicts; do not treat a bulk exit of `0` as proof of patching.

## Reading the result

| Verdict | Meaning | Agent action |
|---|---|---|
| `mitigated` | multipart rejected at the edge (`403`) | report as mitigated, not fixed |
| `exposed` | multipart not rejected **and** PHP evidence on the multipart response | report vulnerable surface, escalate to the PHP owner |
| `inconclusive` | no PHP evidence, multipart response lacked PHP evidence, or PHP down under load | retry once, then report as unproven (not exposed) |
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
  `bulk --workers` multiplies the request footprint across targets; keep `--host-delay` and only
  scan lists you are authorized to assess.
- `POST /` is the default path because it usually 405s — a parser hit with no DB write. Use
  `--path /some/form` with `--method POST` only when you want the full app stack (it writes rows).
- Throttled endpoints surface as `429` and are classified `throttle` (alive, never a vulnerability
  signal).
- Worker death shows as `hang`/`5xx` **with the static control still answering**; FPM respawns
  children, so read `php_worker_deaths`, never the HTTP code alone.
- Never claim a version from this tool. Livewire ≥3 only bounds PHP at ≥8.1. Version truth is
  `php -v` / `dpkg -l | grep php` on the origin.
- Never treat `POST / -> 405` as proof of PHP: static nginx returns the same code. `exposed` needs
  PHP evidence on the host (`php_evidence`) and on the multipart response (`multipart_php_evidence`);
  a 405 without both is `inconclusive`.

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
