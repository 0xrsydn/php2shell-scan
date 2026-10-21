# php2shell-scan

Reachability and change detection for the **php2shell** PHP core RCEs —
CVE-2026-109618 / CVE-2026-109619 (CVSS v4.0 9.2, disclosed 2026-10-20, fixes 2026-10-21 14:00 UTC).

Built for agents and humans who need a defensible answer *without* a public exploit: the bug sits in
PHP's RFC1867 multipart / upload-progress handling, **below** the application, so the reachable code
path can be measured anonymously — no credentials, no CSRF token, no framework knowledge. Because no
PoC existed when this was written, the tool records a **failure profile** and later diffs it.

```
php2shell-scan probe    https://host/                     # 5 requests + size probes, read-only
php2shell-scan baseline https://host/ --save host-pre.json
php2shell-scan verdict  https://host/ host-pre.json        # after the patch
```

## Verdicts

| Verdict | Meaning |
|---|---|
| `mitigated` | multipart rejected at the edge (`403`) — not fixed, just unreachable |
| `exposed` | PHP parses attacker multipart pre-auth: the CVE surface is live |
| `inconclusive` | PHP unconfirmed, or the pool hangs under the probe |
| `improved` | worker deaths vanished vs baseline — a patch smell, confirm with `php -v` |
| `changed` | failure rate moved ≥10 pp on some case — look before concluding |
| `unchanged` | identical to baseline; still vulnerable |
| `no_signal` | flat and deathless both runs — corroboration only, never proof |

Exit `0` mitigated/improved, `1` exposed/unchanged/changed, `2` inconclusive/no_signal.

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
cap a run. Default `--path /` answers `405` on most stacks: a parser hit with no database write.
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
`--max-requests` before `--heavy`, and ask before `--conc 6+`. Nothing is written unless you point
`--path` at a POST route.

MIT licensed.
