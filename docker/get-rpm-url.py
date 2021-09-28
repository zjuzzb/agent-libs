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
from distutils.version import LooseVersion

NAMESPACES={
	'common': 'http://linux.duke.edu/metadata/common',
	'repo': 'http://linux.duke.edu/metadata/repo',
	'rpm': 'http://linux.duke.edu/metadata/rpm'
}

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
	loc = xpath(text, expr, namespaces=NAMESPACES)
	return loc[0].get('href')

def get_by_xpath(text, expr):
	loc = xpath(text, expr, namespaces=NAMESPACES)
	return loc

if __name__ == '__main__':
	baseurl = sys.argv[1]
	pkgname = sys.argv[2]
	try:
		requested_version = LooseVersion(sys.argv[3])
	except IndexError:
		requested_version = None

	repomd = get_url(baseurl + 'repodata/repomd.xml')
	pkglist_url = get_loc_by_xpath(repomd, '//repo:repomd/repo:data[@type="primary"]/repo:location')

	pkglist = get_url(baseurl + pkglist_url, decompress=True)
	pkg_meta = get_by_xpath(pkglist, '//common:metadata/common:package/common:name[text()="{}"]/parent::node()'.format(pkgname))
	pkg_versions = []
	for pkg in pkg_meta:
		version = pkg.find('{http://linux.duke.edu/metadata/common}version')
		# version_str = version.get('epoch') + '.' + version.get('ver') + '.' + version.get('rel')
		version_str = version.get('ver')
		location = pkg.find('{http://linux.duke.edu/metadata/common}location')
		url = location.get('href')
		pkg_versions.append((LooseVersion(version_str), baseurl + url))

	pkg_versions.sort(reverse=True)
	for ver, url in pkg_versions:
		if requested_version is None or requested_version == ver:
			print url
			break

