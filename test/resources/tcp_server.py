import socket
import sys
import os

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

s.bind(("",17643))
s.listen(5)
sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)

print "STARTED"

connect, address = s.accept()

resp = (connect.recv(1024)).strip()
if resp == "SHUTDOWN":
        exit(0)

connect.send(resp)

connect.close()
