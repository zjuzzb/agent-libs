import socket
import time

NUM_REQS = 10000000
REQS_PER_SEC = 5

# Set up a TCP/IP socket

# Connect as client to a selected server
# on a specified port

for j in range(0, NUM_REQS):
#	print j
	s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	s.connect(("localhost",17642))
	s.send("GET /robots.txt HTTP/1.0\n\n")

	# Protocol exchange - sends and receives
	while True:
			resp = s.recv(1024)
			if resp == "": break
#			print resp,

	s.close()

	time.sleep(1.0 / REQS_PER_SEC)

# Close the connection when completed
print "\ndone"
