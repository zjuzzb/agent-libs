import requests
import json
import sys

SYSDIG_URL = "https://app-staging2.sysdigcloud.com"
TOKEN = "b6643f9e-950a-42cf-975f-0dd97d0f0510"

#
# Dashboard Removal
#
def delete_dash(id):
	#
	# setup the headers
	#
	hdrs = {'Authorization': 'Bearer ' + TOKEN, 'Content-Type': 'application/json'}

	#
	# delete the dashboard
	#
	r = requests.delete(SYSDIG_URL + "/ui/dashboards/" + str (id), headers=hdrs)

	print id
	print r

def delete_dash_by_name(name):
	#
	# setup the headers
	#
	hdrs = {'Authorization': 'Bearer ' + TOKEN, 'Content-Type': 'application/json'}

	#
	# Iterate through the dashboards
	#
	r = requests.get(SYSDIG_URL + "/ui/dashboards", headers=hdrs)
	j = r.json()

	for db in j['dashboards']:
		if db['name'] == name:
			id = db['id']
			delete_dash(id)

def delete_dashes():
	#
	# setup the headers
	#
	hdrs = {'Authorization': 'Bearer ' + TOKEN, 'Content-Type': 'application/json'}

	#
	# Iterate through the dashboards
	#
	r = requests.get(SYSDIG_URL + "/ui/dashboards", headers=hdrs)
	j = r.json()

	for db in j['dashboards']:
		id = db['id']

		delete_dash(id)


if len(sys.argv) > 1:
	for j in range(1, len(sys.argv)):
		delete_dash(sys.argv[j])
		delete_dash_by_name(sys.argv[j])
else:
	delete_dashes()
