"""Structure-aware: boundary lines stay intact, damage goes into part headers/values only."""
import http.client, random, re, sys, threading, time, pathlib, json
sys.path.insert(0, "/var/lib/hermes/playground/php2shell-scan")
from php2shell_scan import corpus as C

HOST, PORT = "127.0.0.1", 8090
LOG = pathlib.Path("/tmp/asan-lab/server.log"); OUT = pathlib.Path("/tmp/asan-lab/hits2"); OUT.mkdir(exist_ok=True)
SIG = re.compile(rb"(AddressSanitizer|SEGV|exited on signal|runtime error)")
lock = threading.Lock(); st = {"sent": 0, "hits": 0, "parsed": 0, "codes": {}}
pos = [LOG.stat().st_size if LOG.exists() else 0]
B = b"----zzSEPzz"

def shape():
    parts = []
    for _ in range(random.randint(1, 4)):
        v = random.choice([b"", b"p", b"|".join([b"k"] * random.randint(1, 64)), b"v" * random.randint(1, 512)])
        parts.append((random.choice([b"PHP_SESSION_UPLOAD_PROGRESS", b"PHP_SESSION_UPLOAD_PROGRESS[]",
                                     b"PHP_SESSION_UPLOAD_PROGRESS[a]", b"a", b"f"]), random.random() < .5, v))
    for _ in range(random.randint(1, 3)):
        parts.append((b"f", True, b"Z" * random.randint(0, 4096)))
    random.shuffle(parts)
    out = []
    for name, isfile, val in parts:
        nm = name
        if random.random() < .5 and isfile:
            nm = name + random.choice([b"[]", b"[a][b]", b"[x]" * random.randint(1, 4)])
        hdr = b'Content-Disposition: form-data; name="' + nm + b'"'
        if isfile:
            fn = random.choice([b"a.txt", b"a\x00.php", b"", b'"q".txt', b"a" * random.randint(1, 300), b"a|b[c].txt"])
            hdr += b'; filename="' + fn + b'"'
            if random.random() < .5: hdr += b"\r\nContent-Type: application/octet-stream"
        if random.random() < .2: hdr += b'\r\nX-Pad: ' + b"p" * random.randint(1, 40)
        if random.random() < .1:
            hdr += b'\r\nContent-Disposition: form-data; name="dup"'
        out.append(b"--" + B + b"\r\n" + hdr + b"\r\n\r\n" + val)
    return out

def damage(p: bytes) -> bytes:
    p = bytearray(p)
    for _ in range(random.randint(0, 6)):
        if not p: break
        i = random.randrange(len(p)); r = random.random()
        if r < .35: p[i] = random.choice(b'[]|"\\;=\x00\x7f\r\n \t%')
        elif r < .6: p[i] = random.randrange(256)
        elif r < .8: p[i:i] = p[i:i + random.randint(1, 40)]
        else: del p[i:i + random.randint(1, 16)]
    return bytes(p)

def one(i):
    raw = b"\r\n".join(damage(p) for p in shape()) + b"\r\n--" + B + b"--\r\n"
    hdrs = {"Content-Type": "multipart/form-data; boundary=" + B.decode(), "Connection": "close"}
    if random.random() < .6: hdrs["Cookie"] = f"PHPSESSID=sx{i % 5}"
    try:
        c = http.client.HTTPConnection(HOST, PORT, timeout=30)
        c.request("POST", "/router.php", body=raw, headers=hdrs)
        r = c.getresponse(); body = r.read(); code = r.status; c.close()
        parsed = b'"files":[]' not in body and b'"post":[]' not in body
    except Exception as e:
        code, parsed = f"ERR:{type(e).__name__}", False
        (OUT / f"req-{i}-{code}.bin").write_bytes(raw)
    with lock:
        st["sent"] += 1; st["codes"][str(code)] = st["codes"].get(str(code), 0) + 1; st["parsed"] += bool(parsed)
    if code != 200: (OUT / f"req-{i}-{code}.bin").write_bytes(raw)

def watch():
    while True:
        time.sleep(.12)
        if not LOG.exists(): continue
        sz = LOG.stat().st_size
        if sz <= pos[0]: continue
        ch = LOG.read_bytes()[pos[0]:sz]; pos[0] = sz
        for ln in ch.splitlines():
            if SIG.search(ln):
                st["hits"] += 1
                (OUT / f"HIT-{st['hits']}.log").write_bytes(ln + b"\n")
                print("\n*** HIT", st["hits"], ln.decode('latin-1')[:160], flush=True)

if __name__ == "__main__":
    n = int(sys.argv[1]); conc = int(sys.argv[2]) if len(sys.argv) > 2 else 8
    threading.Thread(target=watch, daemon=True).start()
    live = []
    for i in range(n):
        t = threading.Thread(target=one, args=(i,)); t.start(); live.append(t)
        while sum(1 for x in live if x.is_alive()) >= conc: time.sleep(.01)
        if i % 500 == 0: print(f"{i}/{n} hits={st['hits']} parsed={st['parsed']} codes={st['codes']}", flush=True)
    for t in live: t.join()
    print(json.dumps(st))
