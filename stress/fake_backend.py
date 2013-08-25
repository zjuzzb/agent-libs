import socket
#import MySQLdb as mdb
import sys
import signal

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
      req = connect.recv(65536)
      print len(req)
    except:
      break
