#!/usr/bin/python

import os, sys, json

api_version = "v1"
prefix = "/api/" + api_version + "/"

try:
	jf = open(api_version + ".json", "r")
	js = json.load(jf)

	for api in js['apis']:
		api_path = api['path']

		for op in api['operations']:
			if op['method'] == "GET":
				ord = 1
				name = "name"
				name_space = "namespace"
				path = "path:*"
				msg_name = api_path[len(prefix):].replace('/', '_')

				if name in msg_name:
					msg_name = msg_name.replace('{' + name + '}', name)

				if name_space in msg_name:
					msg_name = msg_name.replace('{' + name_space + '}', name_space)

				if path in msg_name:
					msg_name = msg_name.replace('{' + path + '}', "path")

				print "message " + msg_name + " {"
				params = ""

				for param in op['parameters']:
					if param['required']:
						params = "\trequired "
					else:
						params = "\toptional "

					if param['type'] == "boolean":
						type = "bool"
					else:
						type = param['type']

					params += type + " "
					params += param['name'].replace(path, "path") + " = " + str(ord)
					print params
					ord += 1

				print "}\n"

except IOError:
	print "Error."



