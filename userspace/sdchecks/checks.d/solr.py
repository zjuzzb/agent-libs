import json
import urllib2
from enum import Enum
from sets import Set

from checks import AgentCheck, CheckException
from solr.solr_metrics import SolrMetrics
from solr.solr_5 import Solr5


class Solr(AgentCheck):
    """
    Solr agent check
    """

    METRIC_NAME_MAP = {
        SolrMetrics.METRIC_NAME_ENUM.NONE:                              "solr.unknown",
        SolrMetrics.METRIC_NAME_ENUM.LIVE_NODES:                        "solr.live_nodes",
        SolrMetrics.METRIC_NAME_ENUM.REPLICA:                           "solr.core_count",
        SolrMetrics.METRIC_NAME_ENUM.DOCUMENT_COUNT:                    "solr.document_count",
        SolrMetrics.METRIC_NAME_ENUM.DOCUMENT_COUNT_MAX:                "solr.document_count_max",
        SolrMetrics.METRIC_NAME_ENUM.DOCUMENT_COUNT_DELETED:            "solr.document_count_deleted",
        SolrMetrics.METRIC_NAME_ENUM.BROWSE_RPS:                        "solr.browse.requests_per_second",
        SolrMetrics.METRIC_NAME_ENUM.SELECT_RPS:                        "solr.select.requests_per_second",
        SolrMetrics.METRIC_NAME_ENUM.GET_RPS:                           "solr.get.requests_per_second",
        SolrMetrics.METRIC_NAME_ENUM.QUERY_RPS:                         "solr.query.requests_per_second",
        SolrMetrics.METRIC_NAME_ENUM.UPDATE_RPS:                        "solr.update.requests_per_second",
        SolrMetrics.METRIC_NAME_ENUM.BROWSE_RT:                         "solr.browse.request_time",
        SolrMetrics.METRIC_NAME_ENUM.SELECT_RT:                         "solr.select.request_time",
        SolrMetrics.METRIC_NAME_ENUM.GET_RT:                            "solr.get.request_time",
        SolrMetrics.METRIC_NAME_ENUM.QUERY_RT:                          "solr.query.request_time",
        SolrMetrics.METRIC_NAME_ENUM.UPDATE_RT:                         "solr.update.request_time",
        SolrMetrics.METRIC_NAME_ENUM.INDEX_SIZE_REP:                    "solr.index_size.replicated",
        SolrMetrics.METRIC_NAME_ENUM.INDEX_SIZE_LOG:                    "solr.index_size.logical",
        SolrMetrics.METRIC_NAME_ENUM.HOST_SHARD_COUNT:                  "solr.host.shard_count",
        SolrMetrics.METRIC_NAME_ENUM.COLLECTION_SHARD_COUNT:            "solr.collection.shard_count",
        SolrMetrics.METRIC_NAME_ENUM.UPDATEHANDLER_ADDS:                "solr.updatehandler.adds",
        SolrMetrics.METRIC_NAME_ENUM.UPDATEHANDLER_DELETES_BY_ID:       "solr.updatehandler.deletes_by_id",
        SolrMetrics.METRIC_NAME_ENUM.UPDATEHANDLER_DELETES_BY_QUERY:    "solr.updatehandler.deletes_by_query",
        SolrMetrics.METRIC_NAME_ENUM.UPDATEHANDLER_COMMITS:             "solr.updatehandler.commits",
        SolrMetrics.METRIC_NAME_ENUM.UPDATEHANDLER_AUTOCOMMITS:         "solr.updatehandler.autocommits",
    }

    # Source
    SOURCE_TYPE_NAME = "solr"
    GET_VERSION_ENDPOINT = "/solr/admin/info/system?wt=json"

    def __init__(self, name, init_config, agentConfig, instances=None):
        AgentCheck.__init__(self, name, init_config, agentConfig, instances)
        self.version = None
        self.sMetric = None

    def check(self, instance):
        if self.sMetric is None:
            self._getSolrVersion(instance)

            if self.version is not None and int(self.version[0:1]) == 5:
                self.sMetric = Solr5(self.version, instance)
            elif self.version is None:
                raise CheckException("Failed to find Solr version")
            else:
                raise CheckException("Solr version {} not yet supported".format(self.version[0:1]))

        confTags = instance.get('tags', [])

        ret = self.sMetric.check()

        for metricList in ret:
            if metricList is not None:
                for metric in metricList:
                    if metric is not None and metric.getName() != SolrMetrics.METRIC_NAME_ENUM.NONE:
                        tags = metric.getTags()
                        if tags is not None:
                            tags.extend(confTags)
                        else:
                            tags = confTags

                        if metric.getType() == SolrMetrics.Metric.MetricType.gauge:
                            self.gauge(self.METRIC_NAME_MAP[metric.getName()], metric.getValue(), tags)
                        elif metric.getType() == SolrMetrics.Metric.MetricType.rate:
                            self.rate(self.METRIC_NAME_MAP[metric.getName()], metric.getValue(), tags)

    def _getSolrVersion(self, instance):
        if self.version == None:
            obj, port = SolrMetrics.getUrl(instance["host"], instance["ports"], self.GET_VERSION_ENDPOINT)
            if len(obj) > 0:
                self.log.debug(str("solr: version endpoint found on port {} out of ports {}").format(port, instance["ports"]))
                self.version = obj["lucene"]["solr-spec-version"]
                assert int(self.version[0:1]) >= 4

