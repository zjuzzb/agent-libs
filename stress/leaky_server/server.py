#!/usr/bin/env python
import SimpleHTTPServer
import SocketServer

g_files = []

class MyRequestHandler(SimpleHTTPServer.SimpleHTTPRequestHandler): 
	def do_GET(self):
		if self.path == '/':
			self.path = '/server.py'

		try:
			f = open('log.txt', 'a')
			f.write('Received request from 192.168.1.13\n')
			f = open('log.txt', 'a')
			f.write('seding resource ./server.py\n')
			g_files.append(f)
		except:
			pass

		return SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)

Handler = MyRequestHandler
server = SocketServer.TCPServer(('0.0.0.0', 80), Handler)

server.serve_forever()
