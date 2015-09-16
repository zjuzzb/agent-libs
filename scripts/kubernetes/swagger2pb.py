#!/usr/bin/python

import os, sys, json


API_VERSION = "v1";
PREFIX = "/api/" + API_VERSION + "/";
FILTER = ["pods", "nodes", "services", "replicationcontrollers"];
POD = ["string", "boolean"];


JS = json.load(open(API_VERSION + ".json", "r"));


def output(str):
	print str;


def translate_name(msg_name):
	name = "name";
	name_space = "namespace";
	path = "path:*";

	loc_msg_name = msg_name[len(PREFIX):].replace('/', '_');
	if name in loc_msg_name:
		loc_msg_name = loc_msg_name.replace('{' + name + '}', name);

	if name_space in loc_msg_name:
		loc_msg_name = loc_msg_name.replace('{' + name_space + '}', name_space);

	if path in loc_msg_name:
		loc_msg_name = loc_msg_name.replace('{' + path + '}', "path");

	return loc_msg_name;


def is_POD(type):
	return type in POD;


def translate_POD(type):
	if not is_POD(type):
		raise ValueError("A non-POD data type [" + type + "] cannot be translated.");
	if type == "boolean":
		return "bool";

	return type;


def translate_UDT(type):
	types = JS['models'];
	return types[type];


def translate_type(type):
	if is_POD(type):
		return translate_POD(type);
	else:
		return translate_UDT(type);

	raise ValueError("Unknown or empty data type [" + type + "] cannot be translated.");


def generate_api_calls():
	try:
		for api in JS['apis']:
			api_path = api['path'];

			for op in api['operations']:
				if op['method'] == "GET":
					ord = 1;

					path = "path:*";
					msg_name = translate_name(api_path);

					output("message " + msg_name + " {");
					params = "";

					for param in op['parameters']:
						if param['required']:
							params = "\trequired ";
						else:
							params = "\toptional ";

						type = translate_POD(param['type']);

						params += type + " ";
						params += param['name'].replace(path, "path") + " = " + str(ord) + "; // " + param['description'];
						output(params);
						ord += 1;

					output("}\n");

	except IOError:
		output("Error.");


def generate_responses():
	try:
		models = JS['models'];

		ord = 1;
		object = models[API_VERSION + ".Endpoints"];
		properties = object['properties'];
		output("// " + object['description'].replace('\n', "\n// "));
		output("message k8s_endpoint {");
		for property in properties:
			output("\trequired " + properties['kind']['type'] + ' ' + property + " = " + str(ord) + ';');
			#TODO: expand subsets
			ord += 1;

		output("}\n");

		for api in JS['apis']:
			api_path = api['path'];
			for op in api['operations']:
				if op['method'] == "GET" and "watch" in api_path:
					path_components = translate_name(api_path).split('_');
					#print path_components;
					for entity in FILTER:
						# results with and w/out namespace are identical, so we use namespace only
						# name is 404, so we skip it here (bug? - in any case not critical because
						# it comes in the namespace entry)
						criteria = ((entity in path_components
									and "namespace" in path_components
									and not "name" in path_components) or
									("nodes" in path_components and not "name" in path_components));
						if criteria:
							ord = 1;
							type = op['type'];
							model = models[type]; # always "json.WatchEvent" for watch API
							#print "Raw : " + api_path;
							output("// " + op['summary'] + " (" + model['id'] + ")");
							output("message k8s_" + translate_name(api_path) + " {");
							if type not in POD:
								properties = model['properties'];
								for property in properties:
									if property == "type":
										output("\t// " + model['properties'][property]['description']);
										output("\trequired " + model['properties'][property]['type'] + " type = " + str(ord) + ';');
										ord += 1;
										#print properties[property]['$ref'];
										#TODO: follow the type if non-POD
									elif property == "object":
										output("\t// " + model['properties'][property]['description']);
										output("\trequired k8s_endpoint = " + str(ord) + ';')
										ord += 1;
							else:
								output("Type: " + type);

							output("}\n");
							break;

	except IOError:
		output("Error.");


#generate_api_calls();
generate_responses();
