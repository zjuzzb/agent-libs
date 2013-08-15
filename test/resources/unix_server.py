# -*- coding: utf-8 -*-
import socket
import os, os.path
import time
import sys

NAME = "/tmp/python_unix_sockets_example"
 
if os.path.exists(NAME):
  os.remove(NAME)
 
server = socket.socket( socket.AF_UNIX, socket.SOCK_STREAM )
server.bind(NAME)
sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)

print "STARTED"
server.listen(5)

connect, address = server.accept()
resp = connect.recv( 1024 )
connect.send(resp)
connect.close()
server.close()
os.remove(NAME)
