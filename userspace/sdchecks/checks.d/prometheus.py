# (C) Sysdig, Inc. 2016-2017
# All rights reserved
# Licensed under Simplified BSD License (see LICENSE)

# stdlib
import logging

# 3rd party
import requests

# Prometheus python lib
from prometheus_client.parser import text_string_to_metric_families

# project
from checks import AgentCheck
from sdchecks import AppCheckDontRetryException

class Prometheus(AgentCheck):

    DEFAULT_TIMEOUT = 5
    
    def avg_metric_name(self, name):
        if name.endswith('_count'):
            return name[:-len('_count')] + '_avg'
        else:
            return name[:-len('_sum')] + '_avg'
        
    def check(self, instance):
        if 'url' not in instance:
            raise Exception('Prometheus instance missing "url" value.')

        # Load values from the instance config
        query_url = instance['url']
        max_metrics = instance.get('max_metrics')
        if max_metrics:
            max_metrics = int(max_metrics)
        max_tags = instance.get('max_tags')
        if max_tags:
            max_tags = int(max_tags)

        default_timeout = self.init_config.get('default_timeout', self.DEFAULT_TIMEOUT)
        timeout = float(instance.get('timeout', default_timeout))

        metrics = self.get_prometheus_metrics(query_url, timeout, "prometheus")
        num = 0
        for family in metrics:
            parse_sum = None
            parse_count = None
            if max_metrics and num >= max_metrics:
                break

            for sample in family.samples:
                if max_metrics and num >= max_metrics:
                    break
                (name, tags, value) = sample
                if tags and max_tags and len(tags) > max_tags:
                    tags = {k: tags[k] for k in tags.keys()[:max_tags]}
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
                            # logging.debug('prom: Adding quantile gauge %s.%d' %(name, quantile))
                            self.gauge('%s.%dpercentile' % (name, quantile),
                                       value,
                                       tags)
                            num += 1

                    if parse_sum != None and parse_count > 0:
                        logging.debug('prom: Adding gauge-avg %s' %(self.avg_metric_name(name)))
                        self.gauge(self.avg_metric_name(name), parse_sum/parse_count, tags)
                        num += 1
                elif family.type == 'counter':
                    # logging.debug('prom: adding counter with name %s' %(name))
                    self.rate(name, value, tags)
                    num += 1
                else:
                    # Could be a gauge or untyped value, which we treat as a gauge for now
                    # logging.debug('prom: adding gauge with name %s' %(name))
                    self.gauge(name, value, tags)
                    num += 1

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
            raise AppCheckDontRetryException("Got %s when hitting %s" % (r.status_code, url))
        except (ValueError, requests.exceptions.ConnectionError) as ex:
            raise AppCheckDontRetryException(ex)

        else:
            self.service_check(name, AgentCheck.OK,
                tags = ["url:{0}".format(url)])

        metrics = text_string_to_metric_families(r.text)
        return metrics
