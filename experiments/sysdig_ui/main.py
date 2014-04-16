#!/usr/bin/python
from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer
from os import curdir, sep
import cgi
import json
import subprocess
import base64
import sys
import socket

PORT_NUMBER = 8000

proc = {}


#This class will handles any incoming request from
#the browser 
class myHandler(BaseHTTPRequestHandler):
	#Handler for the GET requests

	def do_AUTHHEAD(self):
		self.send_response(401)
		self.send_header('WWW-Authenticate', 'Basic realm=\"Test\"')
		self.send_header('Content-type', 'text/html')
		self.end_headers()

	def do_GET(self):
		global proc

		if self.path=="/":
			self.path="index.html"
		'''
		if self.path=="/fields":
			self.send_response(200)
			self.send_header('Content-type','application/json')
			self.end_headers()
			res = json.dumps(["a", "b", "c"])
			print res
			self.wfile.write(res)
			return
		'''
		try:
			#Check the file extension required and
			#set the right mime type

			sendReply = False
			if self.path.endswith(".html"):
				mimetype='text/html'
				sendReply = True
			elif self.path.endswith(".jpg"):
				mimetype='image/jpg'
				sendReply = True
			elif self.path.endswith(".png"):
				mimetype='image/png'
				sendReply = True
			elif self.path.endswith(".gif"):
				mimetype='image/gif'
				sendReply = True
			elif self.path.endswith(".js"):
				mimetype='application/javascript'
				sendReply = True
			elif self.path.endswith(".css"):
				mimetype='text/css'
				sendReply = True
			elif self.path.endswith(".json"):
				mimetype='application/json'
				sendReply = True

			if sendReply == True:
				#Open the static file requested and send it
				f = open(curdir + sep + self.path) 
				self.send_response(200)
				self.send_header('Content-type',mimetype)
				self.end_headers()
				self.wfile.write(f.read())
				f.close()
			return

		except IOError:
			self.send_error(404,'File Not Found: %s' % self.path)

	#Handler for the POST requests
	def do_POST(self):
		global proc

		if self.path=="/run":
			content_len = int(self.headers.getheader('content-length'))
			post_body = self.rfile.read(content_len)
			params = json.loads(post_body)
			      
			value = params['value']['field']
			filter = params['value']['filter']
      
			keys = params['key1']['field']
			keydescs = "na"
			
			key2 = params['key2']['field']
			if key2 != '':
				keys += ',' + key2
				keydescs += ",na"
			key3 = params['key3']['field']
			if key3 != '':
				keys += ',' + key3
				keydescs += ",na"
			
			print keys
			
			#
			# Spawn sysdig
			#
			cmd = ["sysdig", "-r", "lo.scap", "-j", "-cmultitable", keys, keydescs, value, "vd", filter, "50", "none"]

			res = subprocess.check_output(cmd)

			self.send_response(200)
			self.end_headers()
			self.wfile.write(res)
			return

#
# If the port is specified on the command line, use it
#
if len(sys.argv) > 1:
	PORT_NUMBER = int(sys.argv[1])
	print PORT_NUMBER

#
#Create a web server and define the handler to manage the
#incoming request
#
server = HTTPServer(('', PORT_NUMBER), myHandler)
print 'Started httpserver on port ' , PORT_NUMBER
	
server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

try:
	#
	# Wait forever for incoming htto requests
	#
	server.serve_forever()

except KeyboardInterrupt:
	print '^C received, shutting down the web server'
	server.socket.close()
