import requests
import json
import sys

SYSDIG_URL = "https://app-staging2.sysdigcloud.com"
TOKEN = "b6643f9e-950a-42cf-975f-0dd97d0f0510"
#2ece4c07-bab4-41c7-9e9c-a716129aa950

#
# Dashboard Creation
#
def create_dash_from_template(newdashname, serviceuid, templatename, servicename):
	#
	# setup the headers
	#
	hdrs = {'Authorization': 'Bearer ' + TOKEN, 'Content-Type': 'application/json'}

	#
	# Get the list of dashboards from the server
	#
	r = requests.get(SYSDIG_URL + "/ui/dashboards", headers=hdrs)
	j = r.json()

	#
	# Find our template dashboard
	#
	dboard = None

	for db in j['dashboards']:
		if db['name'] == templatename:
			dboard = db
			break

	if dboard == None:
		print "can't find dashboard " + templatename
		sys.exit(0)

	#
	# Create the dashboard name
	#
	if newdashname:
		dname = newdashname
	else:
		dname = dboard['name'] + ' for ' + service

	#
	# If this dashboard already exists, don't create it another time
	#
	for db in j['dashboards']:
		if db['name'] == dname:
			print 'dashboard ' + dname + ' already exists'
			return

	#
	# Clean up the dashboard we retireved so it's ready to be pushed
	#
	dboard['id'] = None
	dboard['version'] = None
	dboard['name'] = dname
	
	#
	# Assign the filter and the group ID to each view to point to this service
	#
	filter = {
		"metric" : "kubernetes.service.name",
		"op" : "=",
		"value" : servicename,
		"filters" : None
	}

	j = 0

	for view in dboard['items']:
		j = j + 1

		#
		# create the configuration ID
		#
		confid = newdashname + '-' + serviceuid + '-' + str(j)

		gconf = { "id": confid,
		    "groups": [
		        {
		            "groupBy": [
		                {
		                    "metric": "kubernetes.service.name"
		                }
		            ]
		        }
		    ]
		}

		r = requests.post(SYSDIG_URL + "/api/groupConfigurations", headers=hdrs, data = json.dumps(gconf))

		view['filter'] = filter
		view['groupId'] = confid

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
		serviceuid = item["metadata"]["uid"]

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
					if "name" in dash:
						name = dash["name"]

					if "template" in dash:
						template = dash["template"]
					else:
						print "monitoring-dashboards entry missing the template property"
						sys.exit(0)

					print "  Creating Dashboard %s for user %s based on template %s" %(name, user, template)
					create_dash_from_template(name, serviceuid, template, service)

	

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