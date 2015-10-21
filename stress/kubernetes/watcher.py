import requests
import json
import sys

SYSDIG_URL = 'https://app-staging2.sysdigcloud.com'
TOKEN = 'b6643f9e-950a-42cf-975f-0dd97d0f0510'

###############################################################################
# Create a dashboard for a service
###############################################################################
def create_service_dash_from_template(newdashname, namespace, templatename, servicename):
	#
	# setup the headers
	#
	hdrs = {'Authorization': 'Bearer ' + TOKEN, 'Content-Type': 'application/json'}

	#
	# Create the unique ID for this dashboard
	#
	baseconfid = newdashname + '-' + namespace + '-' + servicename + '-'

	#
	# Get the list of dashboards from the server
	#
	r = requests.get(SYSDIG_URL + '/ui/dashboards', headers=hdrs)
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
		print 'can\'t find dashboard ' + templatename + ' to use asa template'
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
			for view in db['items']:
				if view['groupId'][0:len(baseconfid)] == baseconfid:
					print 'dashboard ' + dname + ' for service ' + servicename + ' already exists'
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
		'filters' : 
		{
			'logic' : 'and',
			'filters' : [ 
				{
					'metric' : 'kubernetes.namespace.name',
					'op' : '=',
					'value' : namespace,
					'filters' : None
				},
				{
					'metric' : 'kubernetes.service.name',
					'op' : '=',
					'value' : servicename,
					'filters' : None
				}
			]
		}
	}

	j = 0

	for view in dboard['items']:
		j = j + 1

		#
		# create the grouping configuration
		#
		confid = baseconfid + str(j)

		gconf = { 'id': confid,
		    'groups': [
		        {
		            'groupBy': [
		                {
		                    'metric': 'kubernetes.namespace.name'
		                },
		                {
		                    'metric': 'kubernetes.service.name'
		                }
		            ]
		        }
		    ]
		}

		r = requests.post(SYSDIG_URL + '/api/groupConfigurations', headers=hdrs, data = json.dumps(gconf))

		view['filter'] = filter
		view['groupId'] = confid

#	print json.dumps(dboard, indent=4, separators=(',', ': '))

	ddboard = {'dashboard': dboard}

	#
	# Create the new dashboard
	#
	r = requests.post(SYSDIG_URL + '/ui/dashboards', headers=hdrs, data = json.dumps(ddboard))
	j = r.json()
	print j

###############################################################################
# Create an alert for a service
###############################################################################
def create_service_alert(name, condition, namespace, servicename):
	#
	# setup the headers
	#
	hdrs = {'Authorization': 'Bearer ' + TOKEN, 'Content-Type': 'application/json'}

	#
	# Create the unique description for this alert
	#
	alert_desc = name + ' for service ' + servicename + ' in namespace ' + namespace

	#
	# Get the list of alerts from the server
	#
	r = requests.get(SYSDIG_URL + '/api/alerts', headers=hdrs)
	j = r.json()

	#
	# Create the alert name
	#
	if name:
		aname = name
	else:
		aname = condition + ' for ' + service

	print '  Creating alert %s for service %s' %(aname, servicename)

	#
	# If this alert already exists, don't create it again
	#
	for db in j['alerts']:
		if db['description'] == alert_desc:
			print 'alert ' + db['name'] + ' for service ' + servicename + ' already exists'
			return

	#
	# Populate the alert information
	#
	alert_json = {
		'alert' : {
			"type" : "MANUAL",
			"name" : name,
			"description" : alert_desc,
			"enabled" : False,
			"filter" : 'kubernetes.namespace.name = "loris" and kubernetes.service.name = "mysql"',
			"severity" : 7,
			"notify" : [ "EMAIL" ],
			"timespan" : 600000000,
			"condition" : condition
		}
	}

  	#
	# Create the new alert
	#
	r = requests.post(SYSDIG_URL + '/api/alerts', headers=hdrs, data = json.dumps(alert_json))
	j = r.json()
	print j

#
# Get the list of k8s services
#
r = requests.get('http://localhost:8080/api/v1/services')
j =r.json()


for item in j['items']:
	if 'metadata' in item:
		service = item['metadata']['name']
		namespace = item['metadata']['namespace']

		print 'Discovered service ' + namespace + ':' + service

		metadata = item['metadata']
		if 'annotations' in metadata:
			annotations = metadata['annotations']

			user = annotations['monitoring-user']

			if 'monitoring-dashboards' in annotations:
				md = annotations['monitoring-dashboards']
	
				dashes = json.loads(md)

				for dash in dashes:
					if 'name' in dash:
						name = dash['name']

					if 'template' in dash:
						template = dash['template']
					else:
						print 'monitoring-dashboards entry missing the template property'
						sys.exit(0)

					#print '  Creating Dashboard %s for user %s based on template %s' %(name, user, template)
					#create_service_dash_from_template(name, namespace, template, service)

					create_service_alert(name, "avg(cpu.used.percent) >= 80", namespace, service)

	

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

'''	
	filter = {
		'metric' : 'kubernetes.service.name',
		'op' : '=',
		'value' : servicename,
		'filters' : None
	}
'''
