import socket
#import MySQLdb as mdb
import sys

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

        # Typically fork at this point

        # Receive up to 1024 bytes
        req = (connect.recv(1024)).strip()

        print req
