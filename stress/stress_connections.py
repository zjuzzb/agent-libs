import httplib
import sys
import random

number_of_connections = 50000
number_of_requests = 1000

connections = dict()
i = 0
while i < number_of_connections:
	connections[i] = httplib.HTTPConnection('127.0.0.1',1337)
	connections[i].connect()
	i = i + 1

print "created connections"

i = 0
while i < number_of_requests:
	connection = connections[random.randint(0,number_of_connections-1)]
	connection.request("GET","/")
	response = connection.getresponse()
	response.read()
	i = i + 1

print "done"