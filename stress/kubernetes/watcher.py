import requests
import json
import sys

SYSDIG_URL = "https://app-staging2.sysdigcloud.com"
TOKEN = "b6643f9e-950a-42cf-975f-0dd97d0f0510"
#2ece4c07-bab4-41c7-9e9c-a716129aa950

#
# Get the list of k8s services
#
r = requests.get('http://localhost:8080/api/v1/services')
j =r.json()

#print j

for item in j["items"]:
	if "metadata" in item:
		metadata = item["metadata"]
		if "annotations" in metadata:
			annotations = metadata["annotations"]

			out = item["metadata"]["name"] + ': ' + annotations["monitoring-user"]
			print out

#
# Dashboard Creation
#

# create the configuration ID
hdrs = {'Authorization': 'Bearer ' + TOKEN, 'Content-Type': 'application/json'}

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
j = r.json()
print j
print "\n"

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

r = requests.post(SYSDIG_URL + "/ui/dashboards", headers=hdrs, data = json.dumps(dboard))
j = r.json()
print j

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
