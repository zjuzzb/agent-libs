import socket

# This is an example of a UDP client - it creates
# a socket and sends data through it

# create the UDP socket
UDPSock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
#UDPSock.bind(('0.0.0.0', 1444))

data = "aaa1234567890\n"

# Simply set up a target address and port ...
addr = ("130.24.36.9",21567)
# ... and send data out to it!
UDPSock.sendto(data,addr)
UDPSock.sendto(data,addr)

print UDPSock.getsockname()

