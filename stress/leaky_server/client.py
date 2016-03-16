#!/usr/bin/env python
import requests
import time
import sys

while True:
	addr = 'http://localhost:80'

	r = requests.get(addr)

	print r
	time.sleep(0.01)
