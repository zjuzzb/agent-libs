import socket
import os
import sys

PAYLOAD = "0123456789QWERTYUIOPASDFGHJKLZXCVBNM"

sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("localhost",17643))

print "STARTED"

s.send(PAYLOAD)
resp = s.recv(1024)

s.close()
