# php2shell-scan

Reachability and change detection for the **php2shell** PHP core RCEs —
CVE-2026-109618 / CVE-2026-109619 (CVSS v4.0 9.2, disclosed 2026-10-20, fixes 2026-10-21 14:00 UTC).

Built for agents and humans who need a defensible answer *without* a public exploit: the bug sits in
PHP's RFC1867 multipart / upload-progress handling, **below** the application, so the reachable code
path can be measured anonymously — no credentials, no CSRF token, no framework knowledge. Because no
PoC existed when this was written, the tool records a **failure profile** and later diffs it.

```
php2shell-scan probe    https://host/                     # ~8 requests + size probes, read-only
php2shell-scan baseline https://host/ --save host-pre.json
php2shell-scan verdict  https://host/ host-pre.json        # after the patch
php2shell-scan bulk     targets.txt --out results/         # many hosts, one summary
```

## Verdicts

| Verdict | Meaning |
|---|---|
| `mitigated` | multipart rejected at the edge (`403`) — not fixed, just unreachable |
| `exposed` | PHP evidence found and attacker multipart is not rejected: the CVE surface is live |
| `inconclusive` | PHP unconfirmed; the multipart response carried no PHP evidence (static `405`/WAF); or the pool hangs |
| `improved` | worker deaths vanished vs baseline — a patch smell, confirm with `php -v` |
| `changed` | failure rate moved ≥10 pp on some case — look before concluding |
| `unchanged` | identical to baseline; still vulnerable |
| `no_signal` | flat and deathless both runs — corroboration only, never proof |

`exposed` requires PHP evidence: an `X-Powered-By: PHP` header, a PHP/framework session cookie, a
redirect to `.php`, or a working `/index.php`. A `POST / -> 405` alone is **not** evidence, because
static nginx returns the same code; without a PHP marker on the multipart response the verdict is
`inconclusive`. The JSON result records `php_evidence` and `multipart_php_evidence` so a host can be
re-checked without re-scanning.

Exit `0` mitigated/improved, `1` exposed/unchanged/changed, `2` inconclusive/no_signal.

## Bulk scanning

`bulk` is the native form of the bash wrapper from issue #1. It reads one target per line, ignores
blank lines and `#` comments, defaults bare hosts to `https://`, removes duplicates, and reports
invalid lines instead of aborting the list.

```bash
php2shell-scan bulk targets.txt --out results/
cat targets.txt | php2shell-scan bulk - --workers 4 --host-timeout 60
php2shell-scan bulk targets.txt --dry-run
```

Each target runs `probe` in its own child process, so `--host-timeout` (default 60 s, `0` disables)
is a hard cap and one wedged host cannot stall the run. Defaults stay polite: sequential
(`--workers 1`) with a 1 s `--host-delay`; `--workers` raises target concurrency only, and per-host
request pacing is still governed by `--delay` / `--rate`. Probe options (`--path`, `--header`,
`--cookie`, `--ua`, `--insecure`, `--max-requests`, `--max-bytes`, ...) apply to every target.

`--quick` skips the 8 MB and 32 MB upload probes (about 41 MB per host) and keeps the multipart and
1 MB probes. Use it for large lists; the reachability verdict and PHP-evidence fields are unchanged.

Results go to `--out` (default `php2shell-results/scan-<UTC>/`; `--out -` disables files):

| File | Content |
|---|---|
| `summary.tsv` | one row per target: verdict, exit, requests, bytes, elapsed, error |
| `summary.json` | combined `bulk` document (schema `php2shell.scan/1`) |
| `summary.txt` | human-readable verdict summary |
| `hosts/NNNN-<host>.json` | full `probe` document for one target |

Bulk exit is aggregate: `1` if any target is `exposed`/`changed`, else `2` if any target is
inconclusive or failed, else `0`. `--format json` puts the combined document on stdout; `--quiet`
suppresses per-target progress. `--dry-run` normalizes and lists targets without sending requests.

A target list can be as simple as:

```
# authorized scope only
example.go.id
https://app.example.go.id/portal
```

Bulk uses the same read-only `probe` (default `POST /`), so a scan of many hosts is still one parser
hit per target rather than an application write.

## Why a profile and not a payload

A body that PHP silently ignores proves nothing. The 24-case corpus is spec-legal but edgy:
upload-progress present / array / `|`-separated / duplicated / colliding with a filename / nested;
14-level bracket names; 200-char and quoted-tspecial boundaries; truncated body; trailing epilogue;
duplicate `Content-Disposition`; RFC5987 `filename*`; NUL filenames; `Content-Transfer-Encoding:
base64`; nested file arrays; 25 files (crosses `max_file_uploads`); heavy: 256 KB part and 1100
parts. `--rand` adds heap-shaping jitter. The unit tests parse every generated body with a real MIME
parser so shapes can't silently rot.

Worker death is the oracle: `5xx`/hang while a static control path still answers, counted as
`php_worker_deaths`. PHP-FPM respawns children, so a crash can masquerade as a clean `200` — always
read the counter, not the status code.

## Guardrails

`--delay 0.3`, `--per-case 1`, no `--heavy` by default. `--rate`, `--max-requests`, `--max-bytes`
cap a run. Default `--path /` answers `405` on most stacks: a parser hit with no database write, but
a `405` alone is not PHP evidence — `exposed` requires a PHP marker, otherwise the result is
`inconclusive`.
`429` is classified `throttle` (alive, not a signal).

`--format json` emits one object with `schema: "php2shell.scan/1"` on stdout; human text goes to
stderr under `--format both`. `--save FILE` persists the document for later `compare`/`verdict`.

## What it cannot do

- **Prove a version.** Livewire ≥3 only bounds PHP at ≥8.1. That's `php -v` or
  `dpkg -l | grep php` on the origin.
- **Prove a patch.** A parser fix needn't change status codes; `no_signal` on a patched host is the
  expected result. This tool corroborates, the ini/version files decide.
- **Escape config false positives.** With `file_uploads=Off` or `session.upload_progress.enabled=Off`
  the surface is narrower than `exposed` suggests.
- **Exploit anything.** It is the instrument that makes a leaked sample trustworthy, not the sample.

## Lab

`lab/` mirrors the target request path (nginx → php-fpm, uploads on, progress on, 4 static workers,
cores enabled) to detonate a sample before it touches production:

```
nix shell nixpkgs#php nixpkgs#nginx -c bash -c 'php-fpm -y lab/fpm.conf & nginx -c lab/nginx.conf -p lab'
python3 lab/fuzz.py --n 200 --conc 4
./lab/detonate.sh /path/to/poc.py
```

Measured there before the advisory: 438 requests on PHP 8.4.19 (both serialize handlers) and 120 on
8.4.26, zero worker deaths — the corpus reaches the code (session files fill with
`upload_progress_<attacker value>|a:5:{…"tmp_name"…}`) but shapes alone don't execute the UAF. See
`lab/README.md`.

## Install

```
pipx install git+https://github.com/0xrsydn/php2shell-scan
# or
git clone https://github.com/0xrsydn/php2shell-scan && python3 -m php2shell_scan probe https://host/
```

Python ≥ 3.9, stdlib only. Tests: `python3 -m unittest discover -s tests`
(`PHP2SHELL_LIVE=https://host/` enables the live checks).

Agent contract: [`SKILL.md`](SKILL.md).

## Scope / ethics

Defaults are polite enough for production, but you are still talking to someone's server: check
`--max-requests` before `--heavy`, and ask before `--conc 6+`. For `bulk`, `--workers` multiplies
that footprint across targets — keep `--host-delay`, and only point it at a list you are authorized
to scan. Nothing is written unless you point `--path` at a POST route.

MIT licensed.
