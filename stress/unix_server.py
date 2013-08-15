# -*- coding: utf-8 -*-
import socket
import os, os.path
import time
import sys
 
if os.path.exists( "/tmp/python_unix_sockets_example" ):
  os.remove( "/tmp/python_unix_sockets_example" )
 
server = socket.socket( socket.AF_UNIX, socket.SOCK_STREAM )
server.bind("/tmp/python_unix_sockets_example")
sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
print >>  sys.stdout, "STARTED"

server.listen(5)

# Servers are "infinite" loops handling requests
while True:
  # Wait for a connection
  connect, address = server.accept()

  datagram = connect.recv( 1024 )
  if not datagram:
    break
  else:
    print datagram
    if "DONE" == datagram:
      break
print "-" * 20
print "Shutting down..."
server.close()
os.remove( "/tmp/python_unix_sockets_example" )
print "Done"
