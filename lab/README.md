# Detonation lab

Local replica of the target's **request path shape** — nginx → FastCGI → php-fpm, uploads on,
`session.upload_progress.enabled=On`, 4 static workers, cores enabled — so an untrusted sample is
fired here before it touches production.

```
nix shell nixpkgs#php nixpkgs#nginx
./lab/start.sh                       # :8081 -> :9000
python3 lab/fuzz.py --n 200 --conc 4 # corpus + randomised heap jitter
./lab/detonate.sh /path/to/poc.py    # sample run; keeps logs, diffs child pids, lists cores
```

Worker death is the oracle: `/tmp/php2shell-lab/fpm-error.log` gains
`child N exited on signal 11 (SIGSEGV)`. `fuzz.py` tails it for you. Read deaths, not HTTP codes —
FPM respawns, so a crash can look like a clean `200`.

Deliberately absent: framework, TLS, auth/CSRF (all irrelevant, the parser is below the app).

Baseline captured 2026-10-21 pre-advisory: 438 requests on PHP 8.4.19 (`php` and `php_serialize`)
and 120 on 8.4.26, zero deaths — corpus reaches the code (session files fill with
`upload_progress_<attacker value>|a:5:{…}`, attacker-controlled keys inside the decode path) but
shapes alone do not execute the UAF. No ASAN build yet: a hit yields a signal and a core, not a
trace.
