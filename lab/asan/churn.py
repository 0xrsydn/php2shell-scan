"""Max update churn: progress + body-field PHPSESSID + multi-MB file (1% freq => ~100 flush cycles)."""
import http.client, random, sys, time, pathlib, re
B=b"----churn"; PORT=8082
LOG=pathlib.Path("/tmp/asan-lab/cgi.log"); pos=[LOG.stat().st_size if LOG.exists() else 0]
SIG=re.compile(rb"(AddressSanitizer|SEGV|exited on signal)")
def part(n,v=b"",fn=None):
    if fn is None: return b"--"+B+b"\r\nContent-Disposition: form-data; name=\""+n+b"\"\r\n\r\n"+v
    return b"--"+B+b"\r\nContent-Disposition: form-data; name=\""+n+b"\"; filename=\""+fn+b"\"\r\nContent-Type: application/octet-stream\r\n\r\n"+v
hits=0
for i in range(int(sys.argv[1])):
    sz=random.choice([1_000_000, 3_000_000, 6_000_000])
    payload=(b"Z"*sz)
    parts=[part(b"PHP_SESSION_UPLOAD_PROGRESS", random.choice([b"p", b"p|q", b"v"*80])),
           part(b"PHPSESSID", random.choice([b"s%d"%(i%3), b"a"*40, b"x|y"]))]
    if random.random()<.5: parts.append(part(b"PHP_SESSION_UPLOAD_PROGRESS", b"dup"))
    parts.append(part(b"f", payload, b"big.bin"))
    if random.random()<.4: parts.insert(0, parts.pop())          # file first
    body=b"\r\n".join(parts)+b"\r\n--"+B+b"--\r\n"
    try:
        c=http.client.HTTPConnection("127.0.0.1",PORT,timeout=120)
        c.request("POST","/index.php",body=body,headers={"Content-Type":"multipart/form-data; boundary="+B.decode()})
        r=c.getresponse(); r.read(); c.close(); code=r.status
    except Exception as e: code="ERR:"+type(e).__name__
    if str(code)!="200": print("  bad",code,sz,flush=True); (pathlib.Path("/tmp/asan-lab/hits3")/f"churn-{i}-{code}.bin").write_bytes(body)
    if i%10==0: print(f"{i} size={sz} code={code}", flush=True)
    time.sleep(0.1)
# check log
sz=LOG.stat().st_size
d=LOG.read_bytes()[pos[0]:sz] if sz>pos[0] else b""
for l in d.splitlines():
    if SIG.search(l): hits+=1; print("*** HIT", l.decode('latin-1')[:200])
print("hits:", hits)
