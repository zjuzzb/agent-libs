import json
import urllib2
from enum import Enum
from sets import Set

from checks import AgentCheck
from solr.solr_metrics import SolrMetrics
from solr.solr_5 import Solr5


class Solr(AgentCheck):
    """
    Solr agent check
    """

    METRIC_NAME_MAP = {
        SolrMetrics.METRIC_NAME_ENUM.LIVE_NODES : "solr.live_nodes",
        SolrMetrics.METRIC_NAME_ENUM.SHARDS: "solr.shards",
        SolrMetrics.METRIC_NAME_ENUM.REPLICA: "solr.replica",
        SolrMetrics.METRIC_NAME_ENUM.DOCUMENT_COUNT: "solr.document_count"
    }

    # Source
    SOURCE_TYPE_NAME = "solr"
    GET_VERSION_ENDPOINT = "/solr/admin/info/system?wt=json"

    def __init__(self, name, init_config, agentConfig, instances=None):
        AgentCheck.__init__(self, name, init_config, agentConfig, instances)
        self.version = None

    def check(self, instance):
        self._get_solr_version(instance)

        if int(self.version[0:1]) == 5:
            self.sMetric = Solr5(self.version, instance)
        else:
            pass

        ret = self.sMetric.check()

        for metric_list in ret:
            if metric_list is not None:
                for metric in metric_list:
                    self.gauge(self.METRIC_NAME_MAP[metric.get_name()], metric.get_value(), metric.get_tags())

    def _get_solr_version(self, instance):
        if self.version == None:
            obj = SolrMetrics.get_url(instance["host"], instance["ports"], self.GET_VERSION_ENDPOINT)
            if len(obj) > 0:
                self.version = obj["lucene"]["solr-spec-version"]
                assert int(self.version[0:1]) >= 4


