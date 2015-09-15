#!/usr/bin/python

import os, sys, json

api_version = "v1"
prefix = "/api/" + api_version + "/"

try:
	jf = open(api_version + ".json", "r")
	js = json.load(jf)

	for api in js['apis']:
		path = api['path']

		for op in api['operations']:
			if op['method'] == "GET":
				print "message " + path[len(prefix):].replace('/', '_') + " {"
				params = ""
				ord = 1

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
					params += param['name'] + " = " + str(ord)
					print params
					ord += 1

				print "}\n"

except IOError:
	print "Error."



