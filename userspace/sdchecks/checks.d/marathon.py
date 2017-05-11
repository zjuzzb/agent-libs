# stdlib
from urlparse import urljoin

# 3rd party
import requests
import simplejson as json

# project
from checks import AgentCheck


class Marathon(AgentCheck):

    DEFAULT_TIMEOUT = 5
    SERVICE_CHECK_NAME = 'marathon.can_connect'

    APP_METRICS = [
        'backoffFactor',
        'backoffSeconds',
        'cpus',
        'dist',
        'instances',
        'mem',
        'taskRateLimit',
        'tasksRunning',
        'tasksStaged'
    ]

    def check(self, instance):
        if 'url' not in instance:
            raise Exception('Marathon instance missing "url" value.')

        # Load values from the instance config
        url = instance['url']
        instance_tags = instance.get('tags', [])
        default_timeout = self.init_config.get('default_timeout', self.DEFAULT_TIMEOUT)
        timeout = float(instance.get('timeout', default_timeout))
        self.auth_token = instance.get('auth_token', '')
        creds = instance.get('marathon_creds', ':')

        # We use mesos credentials only if provided and if no auth token was provided
        if creds == ':' or self.auth_token != '':
            self.auth = None
        else:
            parts = creds.split(":")
            self.auth = (parts[0], parts[1])

        response = self.get_json(urljoin(url, "/v2/apps"), timeout)
        if response is not None:
            self.gauge('marathon.apps', len(response['apps']), tags=instance_tags)
            for app in response['apps']:
                tags = ['app_id:' + app['id'], 'version:' + app['version']] + instance_tags
                for attr in self.APP_METRICS:
                    if attr in app:
                        self.gauge('marathon.' + attr, app[attr], tags=tags)

                query_url = urljoin(url, "/v2/apps/{0}/versions".format(app['id']))
                versions_reply = self.get_json(query_url, timeout)

                if versions_reply is not None:
                    self.gauge('marathon.versions', len(versions_reply['versions']), tags=tags)

    def get_json(self, url, timeout):
        try:
            # Disable gzip enconding that by default requests puts, see below
            headers = {"Accept-Encoding": ""}
            if self.auth_token != '':
                headers["Authorization"] = "token=%s" % (self.auth_token)

            r = requests.get(url, timeout=timeout, auth=self.auth, allow_redirects=False, headers=headers, verify=False, stream=True)
            r.raise_for_status()
        except requests.exceptions.Timeout:
            # If there's a timeout
            self.service_check(self.SERVICE_CHECK_NAME, AgentCheck.CRITICAL,
                message='%s timed out after %s seconds.' % (url, timeout),
                tags = ["url:{0}".format(url)])
            raise Exception("Timeout when hitting %s" % url)

        except requests.exceptions.HTTPError:
            self.service_check(self.SERVICE_CHECK_NAME, AgentCheck.CRITICAL,
                message='%s returned a status of %s' % (url, r.status_code),
                tags = ["url:{0}".format(url)])
            raise Exception("Got %s when hitting %s" % (r.status_code, url))

        except requests.exceptions.SSLError as e:
            self.service_check(self.SERVICE_CHECK_NAME, AgentCheck.CRITICAL,
                message='%s returned a ssl error: %s' % (url, str(e)),
                tags = ["url:{0}".format(url)])
            raise CheckException("Got ssl error %s when hitting %s" % (str(e), url))

        else:
            self.service_check(self.SERVICE_CHECK_NAME, AgentCheck.OK,
                tags = ["url:{0}".format(url)]
            )

        # This hack has been done because parsing a 8 MiB json from memory causes 140 MiB of memory usage
        # in this way the json is parsed as it comes in a streaming fashion
        # we disabled gzip compression because it was hard to implement streaming decompression also
        # we poll only local endpoints here so it should not be an issue
        return json.load(r.raw)
