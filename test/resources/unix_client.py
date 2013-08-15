# -*- coding: utf-8 -*-
import socket
import os, os.path
import time
import sys

PAYLOAD = "0123456789QWERTYUIOPASDFGHJKLZXCVBNM"
NAME = "/tmp/python_unix_sockets_example"

sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)

if os.path.exists(NAME):
  client = socket.socket( socket.AF_UNIX, socket.SOCK_STREAM )
  client.connect(NAME)

  print "STARTED"

  client.send(PAYLOAD)
  resp = client.recv(1024)
  client.close()

else:
	print >> sys.stderr, "Couldn't Connect!"
