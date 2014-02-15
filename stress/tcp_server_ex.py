import socket
#import MySQLdb as mdb
import sys
import time

DELAY_MS = 300

# Establish a TCP/IP socket
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

# Bind to TCP port
s.bind(("",17642))
# ... and listen for anyone to contact you
# queueing up to five requests if you get a backlog
s.listen(5)

# Servers are "infinite" loops handling requests
while True:

        # Wait for a connection
        connect, address = s.accept()

        # Typically fork at this point

        # Receive up to 1024 bytes
        resp = (connect.recv(1024)).strip()
        # And if the user has sent a "SHUTDOWN"
        # instruction, do so (ouch! just a demo)
        if resp == "SHUTDOWN": break

        if DELAY_MS != 0:
                time.sleep(0.001 * DELAY_MS)

        # Send an answer
        connect.send("You said '" + resp + "' to me\n")

        # And there could be a lot more here!

        # When done with a connection close it

        connect.close()
#        print "\ndone",address

        # And loop for / wait for another client
