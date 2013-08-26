import socket
#import MySQLdb as mdb
import sys
import signal
import time
from struct import *

def signal_handler(signal, frame):

  print 'You pressed Ctrl+C!'
  sys.exit(0)
  

PORT = 8080

# Establish a TCP/IP socket
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

# Bind to TCP port
s.bind(("", PORT))
# ... and listen for anyone to contact you
# queueing up to five requests if you get a backlog
s.listen(5)

print("listening on port " + str(PORT))

# Servers are "infinite" loops handling requests
while True:
  # Wait for a connection
  connect, address = s.accept()

  while True:
    try:
      #time.sleep(1)
      #print "ciao"
      #continue
      req = connect.recv(4)
      msglen = socket.ntohl(unpack('i', req)[0])
      print msglen
      req = connect.recv(msglen)
      print len(req) 
      connect.close()
      s.close()
      sys.exit(0)
    except Exception:
      print Exception
      break
