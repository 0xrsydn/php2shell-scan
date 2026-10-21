# ASAN fuzz rig

Builds an instrumented PHP so parser memory errors surface instead of corrupting silently.

```
curl -sSLO https://www.php.net/distributions/php-8.4.19.tar.gz && tar xzf php-8.4.19.tar.gz
cd php-8.4.19
nix shell nixpkgs#gcc nixpkgs#gnumake nixpkgs#bison nixpkgs#re2c nixpkgs#pkg-config -c bash -c '
  export CFLAGS="-fsanitize=address -fno-omit-frame-pointer -O1 -g" LDFLAGS="-fsanitize=address"
  ./configure --disable-all --enable-cli --enable-session --enable-debug --without-pear && make -j$(nproc)'
```

Notes that matter:
- `--disable-all --enable-session` is enough; multipart lives in `main/rfc1867.c` and needs no extension.
- `libxml`/`openssl` fail to configure against nix dev paths — skip them.
- `USE_ZEND_ALLOC=0` is mandatory, otherwise ASAN sees ZendMM's arena instead of real malloc/free.
- `ASAN_OPTIONS=...:halt_on_error=1` + a restart loop, so each hit is terminal and logged.
- Two SAPIs: `run-cli-server.sh` (fast, `php -S` with 4 workers) and `run-cgi.sh` (+ nginx :8082,
  closer to FPM). `fuzz-structured.py` keeps boundary lines intact and damages only part headers and
  values, so requests stay inside the parser.

Result 2026-10-21: ~6,560 requests (2,500 byte-level + 2,000 structured on CLI server + 2,000
structured on CGI/nginx), ~35 % reaching the parser, **zero ASAN reports**. Corpus + blind mutation is
therefore not enough to trip CVE-2026-109618/109619; the trigger needs the advisory.
