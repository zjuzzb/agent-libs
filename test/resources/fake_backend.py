import socket
#import MySQLdb as mdb
import sys
import signal
import ssl
import time
from optparse import OptionParser
from struct import *

def signal_handler(signal, frame):

  print 'You pressed Ctrl+C!'
  sys.exit(0)
  
parser = OptionParser()
parser.add_option("--ssl-key")
parser.add_option("--ssl-certificate")
(options, args) = parser.parse_args()

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

  sock = None

  if options.ssl_certificate is None:
    sock = connect
  else:
    sock = ssl.wrap_socket(connect,
                           server_side=True,
                           certfile=options.ssl_certificate,
                           keyfile=options.ssl_key,
                           ssl_version=ssl.PROTOCOL_TLSv1)

  while True:
    try:
      #time.sleep(1)
      #print "ciao"
      #continue
      req = sock.recv(4)
      msglen = socket.ntohl(unpack('I', req)[0])
      print msglen
      req = sock.recv(msglen)
      print len(req) 
      #sock.close()
      #s.close()
      #sys.exit(0)
    except Exception, e:
      print e
      break
