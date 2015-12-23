# 3p
import simplejson as json

# project
from checks import AgentCheck
import utils.flup_fcgi_client as fcgi_client 

class PHPFPMCheck(AgentCheck):
    """
    Tracks basic php-fpm metrics via the status module
    Requires php-fpm pools to have the status option.
    See http://www.php.net/manual/de/install.fpm.configuration.php#pm.status-path for more details
    """

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

        tags = instance.get('tags', [])

        if status_url is None and ping_url is None:
            raise Exception("No status_url or ping_url specified for this instance")

        pool = None
        status_exception = None
        host = instance.get("host", "localhost")
        port = instance.get("port", 9000)
        if status_url is not None:
            try:
                pool = self._process_status(status_url, host, port, tags)
            except Exception as e:
                status_exception = e
                pass

        if ping_url is not None:
            self._process_ping(ping_url, ping_reply, host, port, tags, pool)

        # pylint doesn't understand that we are raising this only if it's here
        if status_exception is not None:
            raise status_exception  # pylint: disable=E0702

    def _request_url(self, url, query, host, port):
        # Example taken from: http://stackoverflow.com/questions/6801673/python-fastcgi-client
        fcgi = fcgi_client.FCGIApp(host = host, port = port)
        env = {
           'SCRIPT_FILENAME': url,
           'QUERY_STRING': query,
           'REQUEST_METHOD': 'GET',
           'SCRIPT_NAME': url,
           'REQUEST_URI': url,
           'GATEWAY_INTERFACE': 'CGI/1.1',
           'SERVER_SOFTWARE': 'Sysdig Cloud',
           'REDIRECT_STATUS': '200',
           'CONTENT_TYPE': '',
           'CONTENT_LENGTH': '0',
           'DOCUMENT_URI': url,
           'DOCUMENT_ROOT': '/var/www/html',
           #'SERVER_PROTOCOL' : ???
           'REMOTE_ADDR': '127.0.0.1',
           'REMOTE_PORT': '123',
           'SERVER_ADDR': host,
           'SERVER_PORT': str(port),
           'SERVER_NAME': host
           }
        ret = fcgi(env)
        self.log.debug("php-fpm returned: %s" % repr(ret))
        return ret

    def _process_status(self, status_url, host, port, tags):
        data = {}
        try:
            # TODO: adding the 'full' parameter gets you per-process detailed
            # informations, which could be nice to parse and output as metrics
            code, headers, out, err = self._request_url(status_url, "json=true", host, port)
            if code.startswith('200'):
                data = json.loads(out)
            else:
                raise Exception("Wrong response code from %s url" % status_url)
        except Exception as e:
            self.log.error("Failed to get metrics from {0}.\nError {1}".format(status_url, e))
            raise

        pool_name = data.get('pool', 'default')
        metric_tags = tags + ["pool:{0}".format(pool_name)]

        for key, mname in self.GAUGES.iteritems():
            if key not in data:
                self.log.warn("Gauge metric {0} is missing from FPM status".format(key))
                continue
            self.gauge(mname, int(data[key]), tags=metric_tags)

        for key, mname in self.MONOTONIC_COUNTS.iteritems():
            if key not in data:
                self.log.warn("Counter metric {0} is missing from FPM status".format(key))
                continue
            self.monotonic_count(mname, int(data[key]), tags=metric_tags)

        # return pool, to tag the service check with it if we have one
        return pool_name

    def _process_ping(self, ping_url, ping_reply, host, port, tags, pool_name):
        if ping_reply is None:
            ping_reply = 'pong'

        sc_tags = ["ping_url:{0}".format(ping_url)]

        try:
            # TODO: adding the 'full' parameter gets you per-process detailed
            # informations, which could be nice to parse and output as metrics
            code, headers, out, err = self._request_url(ping_url, "", host, port)
            if not code.startswith('200'):
                raise Exception("Wrong response code from %s url" % ping_url)
            if ping_reply not in out:
                raise Exception("Received unexpected reply to ping {0}".format(out))
        except Exception as e:
            self.log.error("Failed to ping FPM pool {0} on URL {1}."
                           "\nError {2}".format(pool_name, ping_url, e))
            self.service_check(self.SERVICE_CHECK_NAME,
                               AgentCheck.CRITICAL, tags=sc_tags, message=str(e))
        else:
            self.service_check(self.SERVICE_CHECK_NAME, AgentCheck.OK, tags=sc_tags)
