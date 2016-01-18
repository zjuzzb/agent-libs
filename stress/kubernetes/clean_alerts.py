import requests
import json
import sys

SYSDIG_URL = "https://app-staging2.sysdigcloud.com"
TOKEN = "b6643f9e-950a-42cf-975f-0dd97d0f0510"

#
# Alert removal
#
def delete_alert(id):
	#
	# setup the headers
	#
	hdrs = {'Authorization': 'Bearer ' + TOKEN, 'Content-Type': 'application/json'}

	#
	# delete the alert
	#
	r = requests.delete(SYSDIG_URL + "/api/alerts/" + str (id), headers=hdrs)

	print id
	print r

def delete_alert_by_name(name):
	#
	# setup the headers
	#
	hdrs = {'Authorization': 'Bearer ' + TOKEN, 'Content-Type': 'application/json'}

	#
	# Iterate through the alert
	#
	r = requests.get(SYSDIG_URL + "/api/alerts", headers=hdrs)
	j = r.json()

	for al in j['alerts']:
		if al['name'] == name:
			id = al['id']
			delete_alert(id)

def delete_alerts():
	#
	# setup the headers
	#
	hdrs = {'Authorization': 'Bearer ' + TOKEN, 'Content-Type': 'application/json'}

	#
	# Iterate through the alerts
	#
	r = requests.get(SYSDIG_URL + "/api/alerts", headers=hdrs)
	j = r.json()

	for al in j['alerts']:
		id = al['id']

		delete_alert(id)


if len(sys.argv) > 1:
	for j in range(1, len(sys.argv)):
		delete_alert(sys.argv[j])
		delete_alert_by_name(sys.argv[j])
else:
	delete_alerts()
