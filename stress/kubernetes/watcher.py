import requests
import json
import sys

K8S_MASTER_URL = 'http://localhost:8080/api/v1/services'
SYSDIG_URL = 'https://app-staging2.sysdigcloud.com'
ADMIN_TOKEN = 'b6643f9e-950a-42cf-975f-0dd97d0f0510'
TMP_USER_TOKEN = 'ebac76a1-cf7b-452c-bcad-8961517da5c5'

user_token = None

def check_response(r):
	if r.status_code >= 300:
		j = r.json()
		print 'code: ' + r.status_code
		print j
		print 'error: ' + j['errors'][0]['message']
		sys.exit(0)


###############################################################################
# Create a dashboard for a service
###############################################################################
def create_service_dash_from_template(newdashname, namespace, templatename, servicename):
	#
	# setup the headers
	#
	hdrs = {'Authorization': 'Bearer ' + user_token, 'Content-Type': 'application/json'}

	#
	# Create the unique ID for this dashboard
	#
	baseconfid = newdashname + '-' + namespace + '-' + servicename + '-'

	#
	# Get the list of dashboards from the server
	#
	r = requests.get(SYSDIG_URL + '/ui/dashboards', headers=hdrs)
	check_response(r)
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
		print 'can\'t find dashboard ' + templatename + ' to use as a template'
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
					print 'dashboard ' + dname + ' for service ' + servicename + ' already exists - ' + baseconfid
					return

	#
	# Clean up the dashboard we retireved so it's ready to be pushed
	#
	dboard['id'] = None
	dboard['version'] = None
	dboard['name'] = dname
	dboard['isShared'] = False # make sure the dashboard is not shared
	
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
		check_response(r)

		view['filter'] = filter
		view['groupId'] = confid

#	print json.dumps(dboard, indent=4, separators=(',', ': '))

	ddboard = {'dashboard': dboard}

	#
	# Create the new dashboard
	#
	r = requests.post(SYSDIG_URL + '/ui/dashboards', headers=hdrs, data = json.dumps(ddboard))
	check_response(r)

###############################################################################
# Create an alert for a service
###############################################################################
def create_service_alert(name, description, condition, for_each, for_atelast_us, severity, namespace, servicename):
	#
	# setup the headers
	#
	hdrs = {'Authorization': 'Bearer ' + user_token, 'Content-Type': 'application/json'}

	#
	# Create the unique description for this alert
	#
	if description:
		alert_desc = description + '(service: ' + servicename + ', namespace: ' + namespace + ')'
	else:
		alert_desc = name + '(service: ' + servicename + ', namespace: ' + namespace + ')'

	#
	# Get the list of alerts from the server
	#
	r = requests.get(SYSDIG_URL + '/api/alerts', headers=hdrs)
	check_response(r)
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
		if 'description' in db:
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

	if for_each != None and for_each != []: 
		alert_json['alert']['segmentBy'] = [ for_each ]
    	alert_json['alert']['segmentCondition'] = { 'type' : 'ANY' }

  	#
	# Create the new alert
	#
	r = requests.post(SYSDIG_URL + '/api/alerts', headers=hdrs, data = json.dumps(alert_json))
	check_response(r)

###############################################################################
# Create a new monitoring user
###############################################################################
def get_user_token(email):
	#
	# setup the headers
	#
	hdrs = {'Authorization': 'Bearer ' + ADMIN_TOKEN, 'Content-Type': 'application/json'}

	#
	# If this user already exists, don't create it again
	#
	r = requests.get(SYSDIG_URL + '/api/users', headers=hdrs)
	check_response(r)
	j = r.json()

	for user in j['users']:
		if 'username' in user:
			if user['username'] == email:
				print 'sysdig cloud user ' + email + ' found'
				# XXX: this will return the real token as soon as the API makes it available
				return TMP_USER_TOKEN

	#
	# User not found, create a new one
	# Populate the alert information
	#
	user_json = { 'username': email }

	r = requests.post(SYSDIG_URL + '/api/users', headers=hdrs, data = json.dumps(user_json))
	check_response(r)
	print 'new sysdig cloud user ' + email + ' created'
	print 'an invitation email has been sent to ' + email

	# XXX: this will return the real token as soon as the API makes it available
	return TMP_USER_TOKEN

###############################################################################
# Add notifications email
###############################################################################
def add_notifications_email(email):
	#
	# setup the headers
	#
	hdrs = {'Authorization': 'Bearer ' + user_token, 'Content-Type': 'application/json'}

	#
	# Retirieve the user's notification settings
	#
	r = requests.get(SYSDIG_URL + '/api/settings/notifications', headers=hdrs)
	check_response(r)
	j = r.json()

	#
	# Enable email notifications
	#
	j['userNotification']['email']['enabled'] = True


	#
	# Add the given recipient
	#
	if not email in j['userNotification']['email']['recipients']:
		j['userNotification']['email']['recipients'].append(email)
		print 'added notification target ' + email
	else:
		print 'notification target ' + email + ' already present'


	r = requests.put(SYSDIG_URL + '/api/settings/notifications', headers=hdrs, data = json.dumps(j))
	check_response(r)

#
# Get the list of k8s services
#
try:
	r = requests.get(K8S_MASTER_URL)
except:
	print 'Connection refused from ' + K8S_MASTER_URL
	sys.exit(0)

j =r.json()


for item in j['items']:
	if 'metadata' in item:
		service = item['metadata']['name']
		namespace = item['metadata']['namespace']

		print 'Discovered service ' + namespace + ':' + service

		metadata = item['metadata']
		if 'annotations' in metadata:
			annotations = metadata['annotations']
					
			if 'monitoring-user' in annotations:
				user_email = annotations['monitoring-user']
				user_token = get_user_token(user_email)
			else:
				user_email = None
				user_token = ADMIN_TOKEN

			if 'alert-recipients' in annotations:
				ar = annotations['alert-recipients']
	
				recipients = json.loads(ar)

				for recipient in recipients:
					add_notifications_email(recipient)

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

					print '  Creating Dashboard %s based on template %s' %(name, template)
					create_service_dash_from_template(name, namespace, template, service)

			if 'monitoring-alerts' in annotations:
				al = annotations['monitoring-alerts']
	
				alerts = json.loads(al)

				for alert in alerts:
					if 'name' in alert:
						name = alert['name']
					else:
						print 'alert entry missing the "name" property'
						sys.exit(0)

					if 'description' in alert:
						description = alert['description']
					else:
						description = None

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

					create_service_alert(name, description, condition, for_each, for_atelast_us, severity, namespace, service)
