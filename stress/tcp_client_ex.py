import socket
import time
import sys

NUM_REQS = 10000000
REQS_PER_SEC = 5
PORT = 17642

if len(sys.argv) > 1:
	PORT = int(sys.argv[1])

j = 0
while True:
	j = j + 1
	if j == NUM_REQS:
		break

	s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	s.connect(("localhost", PORT))
	s.send("GET /robots.txt HTTP/1.0\n\n")

	# Protocol exchange - sends and receives
	while True:
			resp = s.recv(1024)
			if resp == "": break
#			print resp,

	s.close()
	s = 0

	time.sleep(1.0 / REQS_PER_SEC)

# Close the connection when completed
print "\ndone"
