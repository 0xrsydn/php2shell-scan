#!/usr/bin/env python3
"""
Local php2shell fuzz harness: drives multipart / upload-progress shapes at the lab
(nginx :8081 -> php-fpm :9000, pm.static 4) and watches for worker deaths (SIGSEGV etc).

Usage: ./fuzz.py [--n 120] [--conc 1] [--phase attr|load|both] [--seed 1]
Saves any reputation-worthy crash request to lab/crashes/<n>.req plus meta.json.
"""
import argparse, http.client, json, os, random, re, sys, threading, time
from pathlib import Path

HOST, PORT = "127.0.0.1", 8081
LAB = Path(__file__).parent
FPM_LOG = LAB / "../../../../tmp/php2shell-lab/fpm-error.log"
CRASH = LAB / "crashes"
PROG = "PHP_SESSION_UPLOAD_PROGRESS"
SIG = re.compile(rb"(exited on signal|SIGSEGV|SIGBUS|SIGABRT|segmentation)", re.I)

lock = threading.Lock()
state = {"crash": 0, "sent": 0, "codes": {}, "slow": []}
logpos = [os.path.getsize(FPM_LOG) if FPM_LOG.exists() else 0]


def bnd():
    return "----fuzz" + "".join(random.choice("abcdef0123456789") for _ in range(16))


def part(name, value=b"", filename=None):
    out = [b"--B"]
    if filename is None:
        out.append(b'Content-Disposition: form-data; name="%s"' % name.encode())
    else:
        out.append(b'Content-Disposition: form-data; name="%s"; filename="%s"'
                   % (name.encode(), filename.encode()))
        out.append(b"Content-Type: application/octet-stream")
    out.append(b"")
    out.append(value if isinstance(value, bytes) else value.encode())
    return b"\r\n".join(out)


def body_of(parts, end=True):
    b = "\r\n".join(p.decode("latin-1") for p in [])
    raw = b"\r\n".join(parts)
    if end:
        raw += b"\r\n--B--\r\n"
    return raw


def build(case, sid):
    """Return (name, body_bytes, headers) — all shapes carry a file part, progress needs one."""
    nm = b"x"
    filep = part("f", b"A" * 64, filename="a.txt")
    if case == "progress-basic":
        parts = [part(PROG, "p1"), filep]
    elif case == "progress-empty":
        parts = [part(PROG, ""), filep]
    elif case == "progress-long":
        parts = [part(PROG, "x" * 4096), filep]
    elif case == "progress-pipes":
        parts = [part(PROG, "|".join(f"k{i}|v{i}" for i in range(40))), filep]
    elif case == "progress-nested":
        parts = [part(PROG + "[a]" * 12, "v"), filep]
    elif case == "progress-many":
        parts = [part(PROG, f"p{i}") for i in range(10)] + [filep]
    elif case == "progress-after-file":
        parts = [filep, part(PROG, "late")]
    elif case == "progress-as-file":
        parts = [part(PROG, b"v", filename="p.txt"), filep]
    elif case == "progress-name-pipes":
        parts = [part(PROG, "p"), part("f", b"B", filename="a|b[c].txt")]
    elif case == "progress-nul-value":
        parts = [part(PROG, "a\x00b"), filep]
    elif case == "progress-nul-filename":
        parts = [part(PROG, "p"), part("f", b"C", filename="a\x00b.txt")]
    elif case == "progress-urlenc":
        parts = [part(PROG, "%00%7C%5B"), filep]
    elif case == "progress-dup-file":
        parts = [part(PROG, "p"), part("f", b"D", filename="a.txt"), part("f", b"E", filename="b.txt")]
    elif case == "progress-big":
        parts = [part(PROG, "p"), part("f", b"F" * 262144, filename="big.bin")]
    elif case == "progress-no-final":
        parts = [part(PROG, "p"), filep]
        return case, body_of(parts, end=False), sid
    elif case == "clean":
        parts = [filep]
    elif case == "rand":
        parts = []
        for _ in range(random.randint(1, 6)):
            n = random.choice([1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 512])
            parts.append(part(PROG, "v" * n if random.random() < .5 else "|".join("k" * (n // 4))))
        for _ in range(random.randint(0, 3)):
            parts.append(part("f", b"Z" * random.randint(0, 2048), filename="r.txt"))
        if random.random() < .3:   # overflow max_file_uploads
            parts += [part(f"f{i}", b"y", filename=f"{i}.txt") for i in range(25)]
        random.shuffle(parts)
    else:
        raise SystemExit("unknown case " + case)
    return case, body_of(parts), sid


def send(name, body, sid, timeout=60):
    b = bnd()
    body = body.replace(b"--B", b"--" + b.encode())
    hdrs = {"Content-Type": f"multipart/form-data; boundary={b}",
            "Content-Length": str(len(body)), "Connection": "close",
            "User-Agent": "php2shell-fuzz/0.1"}
    if sid:
        hdrs["Cookie"] = f"PHPSESSID={sid}"
    path = "/index.php?sess=1" if random.random() < 0.85 else "/index.php"
    t0 = time.time()
    try:
        c = http.client.HTTPConnection(HOST, PORT, timeout=timeout)
        c.request("POST", path, body=body, headers=hdrs)
        r = c.getresponse(); r.read()
        code = r.status
        c.close()
    except Exception as e:
        code = f"ERR:{type(e).__name__}"
    dt = time.time() - t0
    with lock:
        state["sent"] += 1
        state["codes"][str(code)] = state["codes"].get(str(code), 0) + 1
        if dt > 5:
            state["slow"].append((name, round(dt, 2)))
    if code != 200:
        with lock:
            state.setdefault("bad", []).append((name, code, round(dt, 2)))
    return code


def watch():
    """Tail the FPM log for worker deaths; snapshot the request log for attribution."""
    while not state.get("stop"):
        time.sleep(0.2)
        if not FPM_LOG.exists():
            continue
        sz = os.path.getsize(FPM_LOG)
        if sz <= logpos[0]:
            continue
        with open(FPM_LOG, "rb") as f:
            f.seek(logpos[0]); chunk = f.read()
        logpos[0] = sz
        for line in chunk.splitlines():
            if SIG.search(line):
                state["crash"] += 1
                stamp = time.strftime("%H%M%S")
                (CRASH / f"{stamp}-{state['crash']}.log").write_bytes(chunk)
                print(f"\n*** CRASH #{state['crash']}: {line.decode('latin-1').strip()[:160]}")


CASES = ["rand", "rand", "rand", "clean", "progress-basic", "progress-empty", "progress-long", "progress-pipes",
         "progress-nested", "progress-many", "progress-after-file", "progress-as-file",
         "progress-name-pipes", "progress-nul-value", "progress-nul-filename", "progress-urlenc",
         "progress-dup-file", "progress-big", "progress-no-final"]


def run(n, conc, sess_choices):
    th = threading.Thread(target=watch, daemon=True); th.start()
    inflight = []
    for i in range(n):
        case = CASES[i % len(CASES)]
        sid = random.choice(sess_choices)
        name, body, sid = build(case, sid)
        with lock:
            state.setdefault("log", []).append({"i": i, "case": name, "sid": sid, "len": len(body)})
            req = {"i": i, "case": name, "sid": sid,
                   "headers": {"Content-Type": "multipart/form-data; boundary=<B>",
                               "Cookie": f"PHPSESSID={sid}"},
                   "body_sha_len": len(body)}
        if conc <= 1:
            send(name, body, sid)
        else:
            t = threading.Thread(target=send, args=(name, body, sid)); t.start(); inflight.append(t)
            while sum(1 for x in inflight if x.is_alive()) >= conc:
                time.sleep(0.02)
        if i % 20 == 0:
            print(f"  {i}/{n} crash={state['crash']} codes={state['codes']}", flush=True)
    for t in inflight: t.join()
    state["stop"] = True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=120)
    ap.add_argument("--conc", type=int, default=1)
    ap.add_argument("--sids", type=int, default=3, help="how many distinct session ids to rotate")
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()
    random.seed(a.seed)
    CRASH.mkdir(exist_ok=True)
    sids = [None] + [f"sess{i}" for i in range(a.sids)]
    print(f"lab fuzz: n={a.n} conc={a.conc} sids={sids}")
    run(a.n, a.conc, sids)
    print(json.dumps({"sent": state["sent"], "crashes": state["crash"], "codes": state["codes"],
                      "slow": state["slow"][:10], "bad": (state.get("bad") or [])[:10]}, indent=1))
    return 1 if state["crash"] or state.get("bad") else 0


if __name__ == "__main__":
    sys.exit(main())
