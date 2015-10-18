import requests
import json
import sys

SYSDIG_URL = "https://app-staging2.sysdigcloud.com"
TOKEN = "b6643f9e-950a-42cf-975f-0dd97d0f0510"
#2ece4c07-bab4-41c7-9e9c-a716129aa950

#
# Dashboard Creation
#
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

		print id

		r = requests.delete(SYSDIG_URL + "/ui/dashboards/" + str (id), headers=hdrs)

delete_dashes()
