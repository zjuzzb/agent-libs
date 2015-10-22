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
def create_service_alert(name, condition, for_each, for_atelast_us, severity, namespace, servicename):
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
			'type' : 'MANUAL',
			'name' : name,
			'description' : alert_desc,
			'enabled' : False,
			'filter' : 'kubernetes.namespace.name = "loris" and kubernetes.service.name = "mysql"',
			'severity' : severity,
			'notify' : [ 'EMAIL' ],
			'timespan' : for_atelast_us,
			'condition' : condition
		}
	}

    # "segmentBy" : [ "host.mac" ],
    # "segmentCondition" : { "type" : "ANY" }

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

					#print '  Creating Dashboard %s based on template %s' %(name, template)
					#create_service_dash_from_template(name, namespace, template, service)

			if 'alerts' in annotations:
				al = annotations['alerts']
	
				alerts = json.loads(al)

				for alert in alerts:
					if 'name' in alert:
						name = alert['name']
					else:
						print 'alert entry missing the "name" property'
						sys.exit(0)

					if 'condition' in alert:
						condition = alert['condition']
					else:
						print 'alert entry missing the "condition" property'
						sys.exit(0)

					if 'for_each' in alert:
						for_each = alert['for_each']
					else:
						for_each = None

					if 'for_atelast_us' in alert:
						for_atelast_us = alert['for_atelast_us']
					else:
						for_atelast_us = 60000000

					if 'severity' in alert:
						severity = alert['severity']
					else:
						severity = 6 # Information

					create_service_alert(name, condition, for_each, for_atelast_us, severity, namespace, service)

