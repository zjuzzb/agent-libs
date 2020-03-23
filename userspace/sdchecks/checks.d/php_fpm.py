# (C) Datadog, Inc. 2018
# (C) Sysdig, Inc. 2020
# All rights reserved
# Licensed under Simplified BSD License (see LICENSE)
import json

from six import PY3, StringIO, string_types

from checks import AgentCheck
from utils.common import to_string

if PY3:
    from flup.client.fcgi_app import FCGIApp
else:
    import utils.flup_fcgi_client as fcgi_client
    FCGIApp = fcgi_client.FCGIApp

# Relax param filtering
FCGIApp._environPrefixes.extend(('DOCUMENT_', 'SCRIPT_'))

# Flup as of 1.0.3 is not fully compatible with Python 3 yet.
# This fixes that for our use case.
# https://hg.saddi.com/flup-py3.0/file/tip/flup/client/fcgi_app.py
if PY3:
    import socket

    def get_connection(self):
        if self._connect is not None:
            if isinstance(self._connect, string_types):
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.connect(self._connect)
            elif hasattr(socket, 'create_connection'):
                sock = socket.create_connection(self._connect)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect(self._connect)
            return sock

    FCGIApp._getConnection = get_connection


DEFAULT_TIMEOUT = 20


class BadConfigError(Exception):
    pass


class PHPFPMCheck(AgentCheck):
    """
    Tracks basic php-fpm metrics via the status module
    Requires php-fpm pools to have the status option.
    See http://www.php.net/manual/de/install.fpm.configuration.php#pm.status-path for more details
    """

    NEEDED_NS = ( 'mnt', 'net')
    SERVICE_CHECK_NAME = 'php_fpm.can_ping'

    GAUGES = {
        'listen queue': 'php_fpm.listen_queue.size',
        'idle processes': 'php_fpm.processes.idle',
        'active processes': 'php_fpm.processes.active',
        'total processes': 'php_fpm.processes.total',
    }

    MONOTONIC_COUNTS = {
        'accepted conn': 'php_fpm.requests.accepted',
        'max children reached': 'php_fpm.processes.max_reached',
        'slow requests': 'php_fpm.requests.slow',
    }

    def check(self, instance):
        status_url = instance.get('status_url', '/status')
        ping_url = instance.get('ping_url', '/ping')
        ping_reply = instance.get('ping_reply')
        unix_sock = instance.get('unix_sock')

        tags = instance.get('tags', [])

        if status_url is None and ping_url is None:
            raise BadConfigError("No status_url or ping_url specified for this instance")

        pool = None
        status_exception = None
        host = instance.get("host", "localhost")
        port = instance.get("port", 9000)
        if status_url is not None:
            try:
                pool = self._process_status(status_url, unix_sock, host, port, tags)
            except Exception as e:
                self.log.error("Error running php_fpm check: {}".format(e))

        if ping_url is not None:
            self._process_ping(ping_url, ping_reply, unix_sock, host, port, tags, pool)

    def _process_status(self, status_url, unix_sock, host, port, tags):
        data = {}
        try:
            data = json.loads(self._request_url(status_url, "json=true", unix_sock, host, port))
        except Exception as e:
            self.log.debug("Failed to get metrics from {}: {}".format(status_url, e))
            raise

        pool_name = data.get('pool', 'default')
        metric_tags = tags + ["pool:{0}".format(pool_name)]

        for key, mname in self.GAUGES.items():
            if key not in data:
                self.log.debug("Gauge metric {0} is missing from FPM status".format(key))
                continue
            self.gauge(mname, int(data[key]), tags=metric_tags)

        for key, mname in self.MONOTONIC_COUNTS.items():
            if key not in data:
                self.log.debug("Counter metric {0} is missing from FPM status".format(key))
                continue
            self.rate(mname, int(data[key]), tags=metric_tags)

        # return pool, to tag the service check with it if we have one
        return pool_name

    def _process_ping(self, ping_url, ping_reply, unix_sock, host, port, tags, pool_name):
        if ping_reply is None:
            ping_reply = 'pong'

        sc_tags = ["ping_url:{0}".format(ping_url)] + tags

        try:
            # TODO: adding the 'full' parameter gets you per-process detailed
            # information, which could be nice to parse and output as metrics
            response = self._request_url(ping_url, "", unix_sock, host, port)

            if ping_reply not in response:
                raise Exception("Received unexpected reply to ping: {}".format(response))

        except Exception as e:
            self.log.debug("Failed to ping FPM pool {} on URL {}: {}".format(pool_name, ping_url, e))
            self.service_check(self.SERVICE_CHECK_NAME, AgentCheck.CRITICAL, tags=sc_tags, message=str(e))
        else:
            self.service_check(self.SERVICE_CHECK_NAME, AgentCheck.OK, tags=sc_tags)

    def _request_url(self, url, query, unix_sock, host, port):
        # Example taken from: http://stackoverflow.com/questions/6801673/python-fastcgi-client
        if unix_sock:
            hostname = 'localhost'
            port = '80'
            fcgi = FCGIApp(connect= unix_sock)
        else:
            hostname = host
            if hostname == 'localhost':
                hostname = '127.0.0.1'
            port = str(port)
            fcgi = FCGIApp(host=hostname, port=port)

        env = {
            'CONTENT_LENGTH': '0',
            'CONTENT_TYPE': '',
            'DOCUMENT_ROOT': '/',
            'GATEWAY_INTERFACE': 'FastCGI/1.1',
            'QUERY_STRING': query,
            'REDIRECT_STATUS': '200',
            'REMOTE_ADDR': '127.0.0.1',
            'REMOTE_PORT': '80',
            'REQUEST_METHOD': 'GET',
            'REQUEST_URI': url,
            'SCRIPT_FILENAME': url,
            'SCRIPT_NAME': url,
            'SERVER_ADDR': hostname,
            'SERVER_NAME': hostname,
            'SERVER_PORT': port,
            'SERVER_PROTOCOL': 'HTTP/1.1',
            'SERVER_SOFTWARE': 'Sysdig Agent',
            'wsgi.errors': StringIO(),
            'wsgi.input': StringIO(),
        }

        ret = fcgi(env, lambda *args, **kwargs: '')[0]
        self.log.debug("php-fpm returned: %s" % repr(ret))
        return to_string(ret)
