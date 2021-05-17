#!/usr/bin/env python

### Usage: get-rpm-url.py repo_url package_name
###
### This script:
### 1. Downloads the RPM repo metadata (repomd.xml) to find the URL
###    to the package list (in XML format)
###
### 2. Then downloads the package list and finds the URL to the actual
###    package
###
### 3. Prints the full URL to the package
###
### Example:
### python get-rpm-url.py https://download.sysdig.com/stable/rpm/x86_64/ draios-agent-kmodule
###
### Output:
### https://download.sysdig.com/stable/rpm/x86_64/draios-11.1.3-x86_64-agent-kmodule.rpm

import requests
from lxml import etree
import sys
import zlib

def xpath(text, expr, namespaces):
	e = etree.fromstring(text)
	return e.xpath(expr, namespaces=namespaces)

def get_url(url, decompress=False):
	resp = requests.get(url)
	resp.raise_for_status()
	if decompress:
		return zlib.decompress(resp.content, 47)
	else:
		return resp.content

def get_loc_by_xpath(text, expr):
	loc = xpath(text, expr, namespaces={
		'common': 'http://linux.duke.edu/metadata/common',
		'repo': 'http://linux.duke.edu/metadata/repo',
		'rpm': 'http://linux.duke.edu/metadata/rpm'
	})
	return loc[0].get('href')

if __name__ == '__main__':
	baseurl = sys.argv[1]
	pkgname = sys.argv[2]
	repomd = get_url(baseurl + 'repodata/repomd.xml')
	pkglist_url = get_loc_by_xpath(repomd, '//repo:repomd/repo:data[@type="primary"]/repo:location')

	pkglist = get_url(baseurl + pkglist_url, decompress=True)
	pkg_url = get_loc_by_xpath(pkglist, '//common:metadata/common:package/common:name[text()="{}"]/parent::node()/common:location'.format(pkgname))
	print baseurl + pkg_url
