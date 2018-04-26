from enum import Enum

from solr.solr_metrics import SolrMetrics


class Solr5(SolrMetrics):

    URL = {
        SolrMetrics.Endpoint.CORES_INFO: "http://localhost:8983/solr/admin/info/system?wt=json",
        SolrMetrics.Endpoint.DOCUMENT_COUNT: "/solr/admin/cores?wt=json"
    }

    def __init__(self, version, instance):
        SolrMetrics.__init__(self, version, instance)
        self.cores = frozenset()
        self._get_cores()

    def _get_cores(self):
        obj = self._get_url(self.URL[SolrMetrics.Endpoint.CORES_INFO])
        if len(obj) > 0:
            for name in obj["status"]:
                self.cores.add(name)


    def _get_document_count(self):
        ret = []
        obj = self._get_url(self.URL[SolrMetrics.Endpoint.DOCUMENT_COUNT])
        if len(obj) > 0:
            for replica_alias in obj["status"]:
                splitted = replica_alias.split("_")
                collection = splitted[0]
                shard = splitted[1]
                replica = splitted[2]

                num_docs = obj["status"][replica_alias]["index"]["numDocs"]
                tags = [
                    self.TAG_NAME[self.Tag.COLLECTION] % collection,
                    self.TAG_NAME[self.Tag.SHARD] % shard,
                    self.TAG_NAME[self.Tag.REPLICA] % replica
                ]
                ret.append(self.returnValue(self.METRIC_NAME_ENUM.DOCUMENT_COUNT, num_docs, tags))
        return ret