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

    def __init__(self, name, init_config, agentConfig, instances=None):
        AgentCheck.__init__(self, name, init_config, agentConfig, instances)
        self.metric_history = {}

    def __dump_histogram__(self, keyvals, keys, desc):
        logging.info('======== %s ========' % (desc))
        for k in keys:
            logging.info('[%s]: %s' % (repr(k), repr(keyvals[k])))
        logging.info('======== %s ========' % (desc))

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
        ret_histograms = instance.get("histograms", False)

        default_timeout = self.init_config.get('default_timeout', self.DEFAULT_TIMEOUT)
        timeout = float(instance.get('timeout', default_timeout))
        ssl_verify = instance.get('ssl_verify', False)

        metrics = self.get_prometheus_metrics(query_url, timeout, ssl_verify, "prometheus")
        num = 0
        try:
            for family in metrics:
                parse_sum = None
                parse_count = None
                if max_metrics and num >= max_metrics:
                    break

                name = family.name
                hists = dict()

                for sample in family.samples:
                    if max_metrics and num >= max_metrics:
                        break
                    (sname, stags, value) = sample
                    # convert the dictionary of tags into a list of '<name>:<val>' items
                    # also exclude 'quantile' as a key as it isn't a tag
                    reserved_tags = []
                    if family.type == 'summary':
                        reserved_tags.append('quantile')
                    elif family.type == 'histogram':
                        reserved_tags.append('le')
                    tags = ['{}:{}'.format(k,v) for k,v in stags.iteritems() if k not in reserved_tags]

                    # trim the number of tags to 'max_tags'
                    n_tags = max_tags if max_tags != None else len(tags)
                    tags = tags[:n_tags]

                    hist_entry = None
                    if (family.type == 'histogram') and (ret_histograms != False):
                        hkey = repr(tags)
                        if hkey not in hists:
                            hists[hkey] = {'tags':tags, 'buckets':dict()}
                        hist_entry = hists.get(hkey)

                    # First handle summary
                    # Unused, see above
                    if family.type == 'histogram' or family.type == 'summary':
                        if sname == name + '_sum':
                            parse_sum = value
                        elif sname == name + '_count':
                            parse_count = value
                        else:
                            if (family.type == 'histogram'):
                                if (ret_histograms == False) or ('le' not in stags):
                                    continue
                                bkey = stags['le']
                                if (bkey == '+Inf') or (type(eval(bkey)) in [type(int()), type(float())]):
                                    bkey = float(bkey)
                                else:
                                    logging.error('prom: Unexpected bucket label type/val for %s{%s}' % (sname, stags))
                                hist_entry['buckets'][bkey] = value
                            elif ('quantile' in stags) and (not math.isnan(value)):
                                quantile = int(float(stags['quantile']) * 100)
                                qname = '%s.%dpercentile' % (name, quantile)
                                # logging.debug('prom: Adding quantile gauge %s' %(qname))
                                self.gauge(qname, value, tags)
                                num += 1
                                continue
    
                        if parse_sum != None and parse_count != None:
                            prev = self.metric_history.get(name+str(tags), None) 
                            val = None
                            # The average value over our sample period is:
                            # val = (sum - prev_sum) / (count - prev_count)
                            # We can only find the current average if we have
                            # a previous sample and the count has increased
                            # Otherwise we can't send the current average,
                            # but we'll still send the count (as a rate)
                            if prev and prev.get("sum") != None and prev.get("count") != None:
                                dcnt = parse_count - prev.get("count")
                                if dcnt > 0:
                                    val = (parse_sum - prev.get("sum")) / dcnt
                                elif dcnt < 0:
                                    logging.info('prom: Descending count for %s%s' %(name, repr(tags)))
                            if val != None and not math.isnan(val):
                                # logging.debug('prom: Adding diff-avg %s%s = %s' %(name, repr(tags), str(val)))
                                self.gauge(name+".avg", val, tags)

                            self.rate(name+".count", parse_count, tags)
                            self.metric_history[name+str(tags)] = { "sum":parse_sum, "count":parse_count }
                            # reset refs to sum and count samples in order to
                            # have them point to other segments within the same
                            # family
                            parse_sum = None
                            parse_count = None
                            num += 1
                    elif (family.type == 'counter') and (not math.isnan(value)):
                        # logging.debug('prom: adding counter with name %s' %(name))
                        self.rate(name, value, tags)
                        num += 1
                    elif not math.isnan(value):
                        # Could be a gauge or untyped value, which we treat as a gauge for now
                        # logging.debug('prom: adding gauge with name %s' %(name))
                        self.gauge(name, value, tags)
                        num += 1

                # process the histograms and submit the buckets
                for k,v in hists.iteritems():
                    logging.debug('prom: processing histogram for %s%s' % (name, k))
                    bkeys = sorted(v['buckets'].iterkeys())

                    #self.__dump_histogram__(v['buckets'], bkeys, 'pre-processing')

                    # convert the histograms with cumulative counter to absolute counters
                    if len(v['buckets']) > 1:
                        for i in xrange(len(bkeys)-1, 0, -1):
                            v['buckets'][bkeys[i]] -= v['buckets'][bkeys[i-1]]

                    #self.__dump_histogram__(v['buckets'], bkeys, 'post-processing')

                    self.buckets(name, v['buckets'], v['tags'])
                    num += 1

        # text_string_to_metric_families() generator can raise exceptions
        # for parse values. Treat them all as failures and don't retry.
        except Exception as ex:
            raise AppCheckDontRetryException(ex)

    def get_prometheus_metrics(self, url, timeout, ssl_verify, name):
        try:
            r = requests.get(url, timeout=timeout, verify=ssl_verify)
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
