#!/usr/bin/python
from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer
from os import curdir, sep
from threading  import Thread
import cgi
import json
import subprocess
import base64
import sys
import socket
from subprocess import Popen, PIPE
try:
    from Queue import Queue, Empty
except ImportError:
    from queue import Queue, Empty  # python 3.x

ON_POSIX = 'posix' in sys.builtin_module_names

PORT_NUMBER = 8000
proc = None
readqueue = None
progress = 0

def enqueue_output(out, queue):
    for line in iter(out.readline, b''):
        queue.put(line)
    out.close()

#This class will handles any incoming request from
#the browser 
class myHandler(BaseHTTPRequestHandler):
	def do_AUTHHEAD(self):
		self.send_response(401)
		self.send_header('WWW-Authenticate', 'Basic realm=\"Test\"')
		self.send_header('Content-type', 'text/html')
		self.end_headers()

	def do_GET(self):
		global proc
		global readqueue
		global progress

		if self.path=="/":
			self.path="index.html"
		elif self.path=="/data":
			if proc == None:
				self.send_error(400,'no processing started')
				return

			stdout = proc.stdout.read()
			
			'''
			of = open("sdout.json", "w") 
			of.write(stdout)
			of.close()
			'''

			self.send_response(200)
			self.end_headers()
			self.wfile.write(stdout)

			return
		elif self.path=="/progress":
			if proc == None:
				self.send_error(400,'no processing started')
				return

			while True:
				try:  
					line = readqueue.get_nowait()
				except Empty:
				    break
				else: # got line
					progress = float(line)


			res = json.dumps(progress)

			self.send_response(200)
			self.end_headers()
			self.wfile.write(res)

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
		global readqueue
		global progress

		if self.path=="/run":
			if progress != 0 and progress != 100:
				self.send_error(400,'processing in progress')
				return

			proc = None

			content_len = int(self.headers.getheader('content-length'))
			post_body = self.rfile.read(content_len)
			params = json.loads(post_body)

			value = params['value']['field']
			valuefilter = params['value']['filter']

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

			if params['filter'] != None and params['filter'] != '':
				filter = '(' + params['filter'] + ') and (' + valuefilter + ')'
			else:
				filter = valuefilter

			progress = 0

			#
			# Spawn sysdig
			#
			cmd = ["sysdig", "-P", "-r", "lo.scap", "-j", "-cmultitable", keys, keydescs, "", value, "vd", "SUM", "none", "", filter, "100", "false"]
			print cmd

			proc = subprocess.Popen(cmd, stdout=PIPE, stderr=PIPE, bufsize=1)

			readqueue = Queue()
			t = Thread(target=enqueue_output, args=(proc.stderr, readqueue))
			t.daemon = True # thread dies with the program
			t.start()

			self.send_response(200)
			self.end_headers()
			self.wfile.write("")
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
