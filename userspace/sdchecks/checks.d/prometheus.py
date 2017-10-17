# (C) Sysdig, Inc. 2016-2017
# All rights reserved
# Licensed under Simplified BSD License (see LICENSE)

# stdlib
import logging
import math

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
        try:
            for family in metrics:
                parse_sum = None
                parse_count = None
                if max_metrics and num >= max_metrics:
                    break
    
                for sample in family.samples:
                    if max_metrics and num >= max_metrics:
                        break
                    (name, stags, value) = sample
                    # convert the dictionary of tags into a list of '<name>:<val>' items
                    # also exclude 'quantile' as a key as it isn't a tag
                    tags = ['{}:{}'.format(k,v) for k,v in stags.iteritems() if k != 'quantile']

                    # trim the number of tags to 'max_tags'
                    n_tags = max_tags if max_tags != None else len(tags)
                    tags = tags[:n_tags]
    
                    # First handle summary
                    if family.type == 'histogram' or family.type == 'summary':
                        if name.endswith('_sum'):
                            parse_sum = value
                        elif name.endswith('_count'):
                            parse_count = value
                        else:
                            if family.type == 'histogram':
                                continue
                            elif 'quantile' in stags:
                                quantile = int(float(stags['quantile']) * 100)
                                qname = '%s.%dpercentile' % (name, quantile)
                                # logging.debug('prom: Adding quantile gauge %s' %(qname))
                                self.gauge(qname,
                                           value if not math.isnan(value) else 0,
                                           tags)
                                num += 1
                                continue
    
                        if parse_sum != None and parse_count != None:
                            logging.debug('prom: Adding gauge-avg %s%s' %(self.avg_metric_name(name), repr(tags)))
                            self.gauge(self.avg_metric_name(name),
                                       parse_sum/parse_count if parse_count else 0,
                                       tags)
                            # reset refs to sum and count samples in order to
                            # have them point to other segments within the same
                            # family
                            parse_sum = None
                            parse_count = None
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
        # text_string_to_metric_families() generator can raise exceptions
        # for parse values. Treat them all as failures and don't retry.
        except Exception as ex:
            raise AppCheckDontRetryException(ex)

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

        try:
            metrics = text_string_to_metric_families(r.text)
        # Treat all parse errrors as failures and don't retry.
        except Exception as ex:
            raise AppCheckDontRetryException(ex)
        return metrics
