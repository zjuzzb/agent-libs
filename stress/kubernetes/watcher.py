import requests
import json
import sys

SYSDIG_URL = "https://app-staging2.sysdigcloud.com"
TOKEN = "b6643f9e-950a-42cf-975f-0dd97d0f0510"
#2ece4c07-bab4-41c7-9e9c-a716129aa950

#
# Dashboard Creation
#
def create_dash_from_template(name, templatename, servicename):
	#
	# setup the headers
	#
	hdrs = {'Authorization': 'Bearer ' + TOKEN, 'Content-Type': 'application/json'}

	#
	# Find our template dashboard
	#
	r = requests.get(SYSDIG_URL + "/ui/dashboards", headers=hdrs)
	j = r.json()

	for db in j['dashboards']:
		if db['name'] == templatename:
			dboard = db

	if dboard == None:
		print "can't find dashboard " + templatename
		sys.exit(0)

	#
	# create the configuration ID
	#
	gconf = { "id": "group-configuration-id",
	    "groups": [
	        {
	            "groupBy": [
	                {
	                    "metric": "kubernetes.namespace.name"
	                }
	            ]
	        }
	    ]
	}

	r = requests.post(SYSDIG_URL + "/api/groupConfigurations", headers=hdrs, data = json.dumps(gconf))

	#
	#   Clean up the dashboard we retireved so it's ready to be pushed
	#
	dboard['id'] = None
	dboard['version'] = None

	#
	# Modify the filter of each view to point to this service
	#
	filter = {"filter" : {
		"metric" : "kubernetes.service.name",
		"op" : "=",
		"value" : servicename,
		"filters" : "null"
		}
	}

	for view in dboard['items']:
		view['filter'] = filter

#	print json.dumps(dboard, indent=4, separators=(',', ': '))

	ddboard = {'dashboard': dboard}

	#
	# Create the new dashboard
	#
	r = requests.post(SYSDIG_URL + "/ui/dashboards", headers=hdrs, data = json.dumps(ddboard))
	j = r.json()
	print j

#
# Get the list of k8s services
#
r = requests.get('http://localhost:8080/api/v1/services')
j =r.json()

#print j

for item in j["items"]:
	if "metadata" in item:
		service = item["metadata"]["name"]
		print "Discovered service " + service

		metadata = item["metadata"]
		if "annotations" in metadata:
			annotations = metadata["annotations"]

			user = annotations["monitoring-user"]
			#def create_dash_from_template(templatename):

			if "monitoring-dashboards" in annotations:
				md = annotations["monitoring-dashboards"]
	
				dashes = json.loads(md)

				for dash in dashes:
					if "template" in dash:
						name = dash["name"]
						template = dash["template"]
						print "  Creating Dashboard %s for user %s based on template %s" %(name, user, template)
						create_dash_from_template(name, template, service)

	

#
# Fetch the sysdig users list
#
'''
print "\n"
r = requests.get(SYSDIG_URL + "/api/users", headers=hdrs)

j =r.json()

for user in j["users"]:
	print user["username"]
'''

'''
	# Create the dashboard
	dboard = {
	    "dashboard": {
	        "name": "Lorizzzz",
	        "time": {
	            "last": 1000000
	        },
	        "timeMode": {
	            "mode": 1
	        },
	        "items": [
	            {
	                "name": "Anvedi la CPU",
	                "showAs": "timeSeries",
	                "sourceDescriptor": {
	                    "name": "data"
	                },
	                "filter": {
	                    "metric": "kubernetes.namespace.name",
	                    "op": "=",
	                    "value": "loris"
	                },
	                "groupId": "group-configuration-id",
	                "metrics": [
	#                    {
	#                        "metricId": "host.hostName",
	#                        "propertyName": "k0"
	#                    },
	                    {
	                        "metricId": "container.count",
	                        "propertyName": "v0",
	                        "aggregation": "timeAvg",
	                        "groupAggregation": "avg"
	                    }
	                ],
	                "sorting": [
	                    {
	                        "id": "v0",
	                        "mode": "desc"
	                    }
	                ],
	                "paging": {
	                    "from": 0,
	                    "to": 5
	                },
	                "gridConfiguration": {
	                    "col": 100,
	                    "row": 100,
	                    "size_x": 6,
	                    "size_y": 2
	                }
	            }
	        ]
	    }
	}
'''