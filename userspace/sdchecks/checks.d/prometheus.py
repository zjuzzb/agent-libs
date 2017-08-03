
# stdlib
import logging

# 3rd party
import requests

# Prometheus python lib
from prometheus_client.parser import text_string_to_metric_families

# project
from checks import AgentCheck


class Prometheus(AgentCheck):

    DEFAULT_TIMEOUT = 5
    
    def avg_metric_name(self, name):
        if name.endswith('_count'):
            return name[:-len('_count')] + '_avg'
        else:
            return name[:-len('_sum')] + '_avg'
        
    def check(self, instance):
        logging.debug('Starting app check-prometheus')
        if 'url' not in instance:
            raise Exception('Prometheus instance missing "url" value.')

        # Load values from the instance config
        query_url = instance['url']

        default_timeout = self.init_config.get('default_timeout', self.DEFAULT_TIMEOUT)
        timeout = float(instance.get('timeout', default_timeout))

        metrics = self.get_prometheus_metrics(query_url, timeout, instance.get("name", "prometheus"))
        for family in metrics:
            parse_sum = None
            parse_count = None

            for sample in family.samples:
                (name, tags, value) = sample
                tags = ['{}:{}'.format(k,v) for k,v in tags.iteritems()]

                # First handle summary
                if family.type == 'histogram' or family.type == 'summary':
                    if name.endswith('_sum'):
                        parse_sum = value
                    elif name.endswith('_count'):
                        parse_count = value
                    else:
                        if family.type == 'histogram':
                            continue
                        elif 'quantile' in tags:
                            quantile = int(float(tags['quantile']) * 100)
                            logging.debug('prom: Adding quantile gauge %s.%d' %(name, quantile))
                            self.gauge('%s.%dpercentile' % (name, quantile),
                                       value,
                                       tags)

                    if parse_sum != None and parse_count > 0:
                        logging.debug('prom: Adding gauge-avg %s' %(self.avg_metric_name(name)))
                        self.gauge(self.avg_metric_name(name), parse_sum/parse_count, tags)
                elif family.type == 'counter':
                    logging.debug('prom: adding counter with name %s' %(name))
                    self.rate(name, value, tags)
                else:
                    # Could be a gauge or untyped value, which we treat as a gauge for now
                    logging.debug('prom: adding gauge with name %s' %(name))
                    self.gauge(name, value, tags)

    def get_prometheus_metrics(self, url, timeout, name):
        try:
            r = requests.get(url, timeout=timeout)
            r.raise_for_status()
        except requests.exceptions.Timeout:
            # If there's a timeout
            self.service_check(name, AgentCheck.CRITICAL,
                message='%s timed out after %s seconds.' % (url, timeout),
                tags = ["url:{0}".format(url)])
            raise Exception("Timeout when hitting %s" % url)

        except requests.exceptions.HTTPError:
            self.service_check(name, AgentCheck.CRITICAL,
                message='%s returned a status of %s' % (url, r.status_code),
                tags = ["url:{0}".format(url)])
            raise Exception("Got %s when hitting %s" % (r.status_code, url))

        else:
            self.service_check(name, AgentCheck.OK,
                tags = ["url:{0}".format(url)])

        metrics = text_string_to_metric_families(r.text)
        return metrics
