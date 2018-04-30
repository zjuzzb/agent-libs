from string import split

from enum import Enum

from solr.solr_metrics import SolrMetrics


class Solr5(SolrMetrics):

    URL = {
        SolrMetrics.Endpoint.CORES_INFO: "/solr/admin/cores?wt=json",
        SolrMetrics.Endpoint.DOCUMENT_COUNT: "/solr/admin/cores?wt=json",
        SolrMetrics.Endpoint.STATS: "/solr/%s/admin/mbeans?stats=true&wt=json"
    }

    class RpsMetric:
        def __init__(self, metricName, value):
            self.metricName = metricName
            self.value = value

    def __init__(self, version, instance):
        SolrMetrics.__init__(self, version, instance)
        self.cores = set()

    def _getCores(self):
        obj = self._getUrl(self.URL[SolrMetrics.Endpoint.CORES_INFO])
        if len(obj) > 0:
            for name in obj["status"]:
                self.cores.add(name)


    def _getDocumentCount(self):
        ret = []
        obj = self._getUrl(self.URL[SolrMetrics.Endpoint.DOCUMENT_COUNT])
        if len(obj) > 0:
            for replicaAlias in obj["status"]:
                splitted = replicaAlias.split("_")
                collection = splitted[0]
                shard = splitted[1]
                replica = splitted[2]

                numDocs = obj["status"][replicaAlias]["index"]["numDocs"]
                tags = [
                    self.TAG_NAME[self.Tag.COLLECTION] % collection,
                    self.TAG_NAME[self.Tag.SHARD] % shard,
                    self.TAG_NAME[self.Tag.REPLICA] % replica
                ]
                ret.append(self.Metric(self.METRIC_NAME_ENUM.DOCUMENT_COUNT, numDocs, tags))
        return ret

    def _getAllRps(self):
        ret = []
        coresStatistic = self._getStats()
        for coreStat in coresStatistic:
            # create tags here
            collection, shard, replica = split(coreStat.coreName, "_")
            tags = [
                self.TAG_NAME[self.Tag.COLLECTION] % collection,
                self.TAG_NAME[self.Tag.SHARD] % shard,
                self.TAG_NAME[self.Tag.REPLICA] % replica
            ]
            all_rps = self._getFromCoreRps(coreStat.data)
            for rps in all_rps:
                ret.append(self.Metric(rps.metricName, rps.value, tags))
        return ret, coresStatistic

    def _getIndexSize(self, coresStatisticJson):
        ret = []
        for coreStatistic in coresStatisticJson:
            ret.append(self._getFromCoreIndexSize(coreStatistic))
        return ret

    def _getStats(self):
        class CoreStat:
            pass
        ret = []
        self._getCores()
        for core in self.cores:
            element = CoreStat
            element.coreName = core
            element.data = self._getSingleCoreStats(self._generateUrl(core))
            ret.append(element)
        return ret

    def _generateUrl(self, core):
        return self.URL[SolrMetrics.Endpoint.STATS] % core

    def _getSingleCoreStats(self, url):
        return self._getUrl(url)

    def _getFromCoreRps(self, obj):
        arr = []

        # in solr 5, a map has been implemented as an array in which
        # first is put the key, and then the value
        beans = obj["solr-mbeans"]
        assert beans[2] == "QUERYHANDLER"
        queryHandlerObj = beans[3]

        arr.append(self._getSingleRps(SolrMetrics.METRIC_NAME_ENUM.BROWSE_RPS, "/browse", queryHandlerObj))
        arr.append(self._getSingleRps(SolrMetrics.METRIC_NAME_ENUM.SELECT_RPS, "/select", queryHandlerObj))
        arr.append(self._getSingleRps(SolrMetrics.METRIC_NAME_ENUM.GET_RPS, "/get", queryHandlerObj))
        arr.append(self._getSingleRps(SolrMetrics.METRIC_NAME_ENUM.QUERY_RPS, "/query", queryHandlerObj))
        arr.append(self._getSingleRps(SolrMetrics.METRIC_NAME_ENUM.UPDATE_RPS, "/update", queryHandlerObj))
        return arr

    def _getSingleRps(self, metricEnumValue, keyString, queryHandlerObj):
        return self.RpsMetric(metricEnumValue, queryHandlerObj[keyString]["stats"]["avgRequestsPerSecond"])

    def _getFromCoreIndexSize(self, coreStatistic ):
        collection, shard, replica = split(coreStatistic.coreName, "_")
        tags = [
            self.TAG_NAME[self.Tag.COLLECTION] % collection,
            self.TAG_NAME[self.Tag.SHARD] % shard,
            self.TAG_NAME[self.Tag.REPLICA] % replica
        ]
        sizeInBytes, unit = split(coreStatistic.data["solr-mbeans"][3]["/replication"]["stats"]["indexSize"], " ")
        ret = self.Metric(SolrMetrics.METRIC_NAME_ENUM.INDEX_SIZE, int(sizeInBytes), tags)
        return ret
