# -*- coding: utf-8 -*-
import socket
import os, os.path
import time
import sys
sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
print "STARTED"
print "Connecting..."
if os.path.exists( "/tmp/python_unix_sockets_example" ):
  client = socket.socket( socket.AF_UNIX, socket.SOCK_STREAM )
  client.connect( "/tmp/python_unix_sockets_example" )
  print "Ready."
  try:
    client.send( "DONE" )
  except KeyboardInterrupt, k:
    print "Shutting down."
  client.close()
else:
  print "Couldn't Connect!"

print "Done"
