import ConfigParser
from cStringIO import StringIO
import glob
import imp
import inspect
import itertools
import logging
import logging.config
import logging.handlers
from optparse import OptionParser, Values
import os
import platform
import re
from socket import gaierror, gethostbyname
import string
import sys
import traceback
from urlparse import urlparse

# 3rd party
import yaml

# project
from util import get_os, yLoader
from utils.platform import Platform
from utils.proxy import get_proxy
from utils.subprocess_output import subprocess

# CONSTANTS
AGENT_VERSION = "5.5.0"
DEFAULT_CHECK_FREQUENCY = 15   # seconds
LOGGING_MAX_BYTES = 5 * 1024 * 1024

log = logging.getLogger(__name__)

OLD_STYLE_PARAMETERS = [
    ('apache_status_url', "apache"),
    ('cacti_mysql_server' , "cacti"),
    ('couchdb_server', "couchdb"),
    ('elasticsearch', "elasticsearch"),
    ('haproxy_url', "haproxy"),
    ('hudson_home', "Jenkins"),
    ('memcache_', "memcached"),
    ('mongodb_server', "mongodb"),
    ('mysql_server', "mysql"),
    ('nginx_status_url', "nginx"),
    ('postgresql_server', "postgres"),
    ('redis_urls', "redis"),
    ('varnishstat', "varnish"),
    ('WMI', "WMI"),
]

NAGIOS_OLD_CONF_KEYS = [
    'nagios_log',
    'nagios_perf_cfg'
]


class PathNotFound(Exception):
    pass


def get_parsed_args():
    parser = OptionParser()
    parser.add_option('-A', '--autorestart', action='store_true', default=False,
                      dest='autorestart')
    parser.add_option('-d', '--dd_url', action='store', default=None,
                      dest='dd_url')
    parser.add_option('-u', '--use-local-forwarder', action='store_true',
                      default=False, dest='use_forwarder')
    parser.add_option('-n', '--disable-dd', action='store_true', default=False,
                      dest="disable_dd")
    parser.add_option('-v', '--verbose', action='store_true', default=False,
                      dest='verbose',
                      help='Print out stacktraces for errors in checks')
    parser.add_option('-p', '--profile', action='store_true', default=False,
                      dest='profile', help='Enable Developer Mode')

    try:
        options, args = parser.parse_args()
    except SystemExit:
        # Ignore parse errors
        options, args = Values({'autorestart': False,
                                'dd_url': None,
                                'disable_dd':False,
                                'use_forwarder': False,
                                'profile': False}), []
    return options, args


def get_version():
    return AGENT_VERSION


def skip_leading_wsp(f):
    "Works on a file, returns a file-like object"
    return StringIO("\n".join(map(string.strip, f.readlines())))


def _windows_commondata_path():
    """Return the common appdata path, using ctypes
    From http://stackoverflow.com/questions/626796/\
    how-do-i-find-the-windows-common-application-data-folder-using-python
    """
    import ctypes
    from ctypes import wintypes, windll

    CSIDL_COMMON_APPDATA = 35

    _SHGetFolderPath = windll.shell32.SHGetFolderPathW
    _SHGetFolderPath.argtypes = [wintypes.HWND,
                                ctypes.c_int,
                                wintypes.HANDLE,
                                wintypes.DWORD, wintypes.LPCWSTR]

    path_buf = wintypes.create_unicode_buffer(wintypes.MAX_PATH)
    result = _SHGetFolderPath(0, CSIDL_COMMON_APPDATA, 0, 0, path_buf)
    return path_buf.value


def _unix_checksd_path():
    # Unix only will look up based on the current directory
    # because checks.d will hang with the other python modules
    cur_path = os.path.dirname(os.path.realpath(__file__))
    checksd_path = os.path.join(cur_path, 'checks.d')

    if os.path.exists(checksd_path):
        return checksd_path
    raise PathNotFound(checksd_path)


def _is_affirmative(s):
    # int or real bool
    if isinstance(s, int):
        return bool(s)
    # try string cast
    return s.lower() in ('yes', 'true', '1')


def get_default_bind_host():
    try:
        gethostbyname('localhost')
    except gaierror:
        log.warning("localhost seems undefined in your hosts file, using 127.0.0.1 instead")
        return '127.0.0.1'
    return 'localhost'


def get_histogram_aggregates(configstr=None):
    if configstr is None:
        return None

    try:
        vals = configstr.split(',')
        valid_values = ['min', 'max', 'median', 'avg', 'count']
        result = []

        for val in vals:
            val = val.strip()
            if val not in valid_values:
                log.warning("Ignored histogram aggregate {0}, invalid".format(val))
                continue
            else:
                result.append(val)
    except Exception:
        log.exception("Error when parsing histogram aggregates, skipping")
        return None

    return result

def get_histogram_percentiles(configstr=None):
    if configstr is None:
        return None

    result = []
    try:
        vals = configstr.split(',')
        for val in vals:
            try:
                val = val.strip()
                floatval = float(val)
                if floatval <= 0 or floatval >= 1:
                    raise ValueError
                if len(val) > 4:
                    log.warning("Histogram percentiles are rounded to 2 digits: {0} rounded"
                        .format(floatval))
                result.append(float(val[0:4]))
            except ValueError:
                log.warning("Bad histogram percentile value {0}, must be float in ]0;1[, skipping"
                    .format(val))
    except Exception:
        log.exception("Error when parsing histogram percentiles, skipping")
        return None

    return result


def get_system_stats():
    systemStats = {
        'machine': platform.machine(),
        'platform': sys.platform,
        'processor': platform.processor(),
        'pythonV': platform.python_version(),
    }

    platf = sys.platform

    if Platform.is_linux(platf):
        grep = subprocess.Popen(['grep', 'model name', '/proc/cpuinfo'], stdout=subprocess.PIPE, close_fds=True)
        wc = subprocess.Popen(['wc', '-l'], stdin=grep.stdout, stdout=subprocess.PIPE, close_fds=True)
        systemStats['cpuCores'] = int(wc.communicate()[0])

    if Platform.is_darwin(platf):
        systemStats['cpuCores'] = int(subprocess.Popen(['sysctl', 'hw.ncpu'], stdout=subprocess.PIPE, close_fds=True).communicate()[0].split(': ')[1])

    if Platform.is_freebsd(platf):
        systemStats['cpuCores'] = int(subprocess.Popen(['sysctl', 'hw.ncpu'], stdout=subprocess.PIPE, close_fds=True).communicate()[0].split(': ')[1])

    if Platform.is_linux(platf):
        systemStats['nixV'] = platform.dist()

    elif Platform.is_darwin(platf):
        systemStats['macV'] = platform.mac_ver()

    elif Platform.is_freebsd(platf):
        version = platform.uname()[2]
        systemStats['fbsdV'] = ('freebsd', version, '')  # no codename for FreeBSD

    elif Platform.is_win32(platf):
        systemStats['winV'] = platform.win32_ver()

    return systemStats


def get_confd_path(osname=None):
    if not osname:
        osname = get_os()
    bad_path = ''
    if osname == 'windows':
        try:
            return _windows_confd_path()
        except PathNotFound, e:
            if len(e.args) > 0:
                bad_path = e.args[0]
    else:
        try:
            return _unix_confd_path()
        except PathNotFound, e:
            if len(e.args) > 0:
                bad_path = e.args[0]

    cur_path = os.path.dirname(os.path.realpath(__file__))
    cur_path = os.path.join(cur_path, 'conf.d')

    if os.path.exists(cur_path):
        return cur_path

    raise PathNotFound(bad_path)


def get_checksd_path(osname=None):
    if not osname:
        osname = get_os()
    if osname == 'windows':
        return _windows_checksd_path()
    else:
        return _unix_checksd_path()


def get_win32service_file(osname, filename):
    # This file is needed to log in the event viewer for windows
    if osname == 'windows':
        if hasattr(sys, 'frozen'):
            # we're frozen - from py2exe
            prog_path = os.path.dirname(sys.executable)
            path = os.path.join(prog_path, filename)
        else:
            cur_path = os.path.dirname(__file__)
            path = os.path.join(cur_path, filename)
        if os.path.exists(path):
            log.debug("Certificate file found at %s" % str(path))
            return path

    else:
        cur_path = os.path.dirname(os.path.realpath(__file__))
        path = os.path.join(cur_path, filename)
        if os.path.exists(path):
            return path

    return None


def get_ssl_certificate(osname, filename):
    # The SSL certificate is needed by tornado in case of connection through a proxy
    if osname == 'windows':
        if hasattr(sys, 'frozen'):
            # we're frozen - from py2exe
            prog_path = os.path.dirname(sys.executable)
            path = os.path.join(prog_path, filename)
        else:
            cur_path = os.path.dirname(__file__)
            path = os.path.join(cur_path, filename)
        if os.path.exists(path):
            log.debug("Certificate file found at %s" % str(path))
            return path

    else:
        cur_path = os.path.dirname(os.path.realpath(__file__))
        path = os.path.join(cur_path, filename)
        if os.path.exists(path):
            return path


    log.info("Certificate file NOT found at %s" % str(path))
    return None

def check_yaml(conf_path):
    f = open(conf_path)
    check_name = os.path.basename(conf_path).split('.')[0]
    try:
        check_config = yaml.load(f.read(), Loader=yLoader)
        assert 'init_config' in check_config, "No 'init_config' section found"
        assert 'instances' in check_config, "No 'instances' section found"

        valid_instances = True
        if check_config['instances'] is None or not isinstance(check_config['instances'], list):
            valid_instances = False
        else:
            for i in check_config['instances']:
                if not isinstance(i, dict):
                    valid_instances = False
                    break
        if not valid_instances:
            raise Exception('You need to have at least one instance defined in the YAML file for this check')
        else:
            return check_config
    finally:
        f.close()