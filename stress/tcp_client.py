import socket

# Set up a TCP/IP socket
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

# Connect as client to a selected server
# on a specified port
s.connect(("localhost",17640))
#s.connect(("www.wellho.net",80))


# Protocol exchange - sends and receives
s.send("GET /robots.txt HTTP/1.0\n\n")
while True:
        resp = s.recv(1024)
        if resp == "": break
        print resp,

# Close the connection when completed
print s.getsockname()
s.close()
print "\ndone"
