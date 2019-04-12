"""
This module contains a list of internal modules required by app checks,
some of which can sometimes be missing when namespace is switched,
leading to name resolution errors. This common module is designed
to be a common module that can be imported by all app checks.
"""
import _strptime
from xml.parsers import expat
import requests.packages.chardet.universaldetector
