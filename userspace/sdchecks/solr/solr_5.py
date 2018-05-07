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

    def _getLocalCores(self):
        for baseUrl in self.localEndpoints:
            try:
                obj = self._getUrlWithBase(baseUrl, self.URL[SolrMetrics.Endpoint.CORES_INFO])
                if len(obj) > 0:
                    for name in obj["status"]:
                        self.cores.add(name)
            except Exception as e:
                self.log.error(("could not get cores for endpoint {}: {}").format(baseUrl, e))


    def _getDocumentCount(self):
        ret = []
        for baseUrl in self.localEndpoints:
            try:
                obj = self._getUrlWithBase(baseUrl, self.URL[SolrMetrics.Endpoint.DOCUMENT_COUNT])
                if len(obj) > 0:
                    totalDocumentsInNode = 0
                    for replicaAlias in obj["status"]:
                        if replicaAlias in self.localCores:
                            splitted = replicaAlias.split("_")
                            collection = splitted[0]
                            shard = splitted[1]
                            replica = splitted[2]

                            numDocs = obj["status"][replicaAlias]["index"]["numDocs"]
                            totalDocumentsInNode = totalDocumentsInNode + numDocs
                            tags = [
                                self.TAG_NAME[self.Tag.COLLECTION] % collection,
                                self.TAG_NAME[self.Tag.SHARD] % shard,
                                self.TAG_NAME[self.Tag.REPLICA] % replica,
                                self.TAG_NAME[self.Tag.CORE] % replicaAlias
                            ]
                            ret.append(self.Metric(self.METRIC_NAME_ENUM.DOCUMENT_COUNT, numDocs, tags))
                    self.log.debug(str("found {} documents in local node {}").format(totalDocumentsInNode, baseUrl))
            except Exception as e:
                self.log.error(("could not get document count for endpoint {}: {}").format(baseUrl, e))
        return ret

    def _getAllRpsAndRequestTime(self):
        ret = []
        coresStatistic = self._getStats()
        self.log.debug(str("fetching statistics for {} local cores").format(len(coresStatistic)))
        for coreStat in coresStatistic:
            # create tags here
            collection, shard, replica = split(coreStat.coreName, "_")
            tags = [
                self.TAG_NAME[self.Tag.COLLECTION] % collection,
                self.TAG_NAME[self.Tag.SHARD] % shard,
                self.TAG_NAME[self.Tag.REPLICA] % replica,
                self.TAG_NAME[self.Tag.CORE] % coreStat.coreName
            ]
            all_rps = self._getFromCoreRpsAndRequestTime(coreStat.data)
            for rps in all_rps:
                ret.append(self.Metric(rps.metricName, rps.value, tags))
        return ret

    def _getIndexSize(self):
        ret = []
        coresStatisticJson = self._getStats()
        self.log.debug(str("fetching index memory size for {} local cores").format(len(coresStatisticJson)))
        for coreStatistic in coresStatisticJson:
            ret.append(self._getFromCoreIndexSize(coreStatistic))
        return ret

    def _getStats(self):
        class CoreStat:
            pass
        ret = []
        self._getLocalCores()
        for core in self.cores:
            element = CoreStat()
            element.coreName = core
            element.data = self._getSingleCoreStats(self._generateUrl(core))
            ret.append(element)
        return ret

    def _generateUrl(self, core):
        return self.URL[SolrMetrics.Endpoint.STATS] % core

    def _getSingleCoreStats(self, url):
        return self._getUrl(url)

    def _getFromCoreRpsAndRequestTime(self, obj):
        arr = []

        # in solr 5, a map has been implemented as an array in which
        # first is put the key, and then the value
        try:
            beans = obj["solr-mbeans"]
            assert beans[2] == "QUERYHANDLER"
            queryHandlerObj = beans[3]

            arr.append(self._getSingleRps(SolrMetrics.METRIC_NAME_ENUM.BROWSE_RPS, "/browse", queryHandlerObj))
            arr.append(self._getSingleRps(SolrMetrics.METRIC_NAME_ENUM.SELECT_RPS, "/select", queryHandlerObj))
            arr.append(self._getSingleRps(SolrMetrics.METRIC_NAME_ENUM.GET_RPS, "/get", queryHandlerObj))
            arr.append(self._getSingleRps(SolrMetrics.METRIC_NAME_ENUM.QUERY_RPS, "/query", queryHandlerObj))
            arr.append(self._getSingleRps(SolrMetrics.METRIC_NAME_ENUM.UPDATE_RPS, "/update", queryHandlerObj))

            arr.append(self._getSingleRequestTime(SolrMetrics.METRIC_NAME_ENUM.BROWSE_RT, "/browse", queryHandlerObj))
            arr.append(self._getSingleRequestTime(SolrMetrics.METRIC_NAME_ENUM.SELECT_RT, "/select", queryHandlerObj))
            arr.append(self._getSingleRequestTime(SolrMetrics.METRIC_NAME_ENUM.GET_RT, "/get", queryHandlerObj))
            arr.append(self._getSingleRequestTime(SolrMetrics.METRIC_NAME_ENUM.QUERY_RT, "/query", queryHandlerObj))
            arr.append(self._getSingleRequestTime(SolrMetrics.METRIC_NAME_ENUM.UPDATE_RT, "/update", queryHandlerObj))
        except Exception as e:
            self.log.error(("could not get statistic from local cores: {}").format(e))
        return arr

    def _getSingleRps(self, metricEnumValue, keyString, queryHandlerObj):
        try:
            return self.RpsMetric(metricEnumValue, queryHandlerObj[keyString]["stats"]["avgRequestsPerSecond"])
        except Exception as e:
            self.log.error(("could not get rps {} {}: {}").format(metricEnumValue, keyString. e))
            return self.RpsMetric(SolrMetrics.METRIC_NAME_ENUM.NONE, 0)

    def _getSingleRequestTime(self, metricEnumValue, keyString, queryHandlerObj):
        try:
            return self.RpsMetric(metricEnumValue, float(queryHandlerObj[keyString]["stats"]["avgTimePerRequest"]))
        except Exception as e:
            self.log.error(("could not get request time {} {}: {}").format(metricEnumValue, keyString.e))
            return self.RpsMetric(SolrMetrics.METRIC_NAME_ENUM.NONE, 0)

    def _getFromCoreIndexSize(self, coreStatistic ):
        collection, shard, replica = split(coreStatistic.coreName, "_")
        tags = [
            self.TAG_NAME[self.Tag.COLLECTION] % collection,
            self.TAG_NAME[self.Tag.SHARD] % shard,
            self.TAG_NAME[self.Tag.REPLICA] % replica,
            self.TAG_NAME[self.Tag.CORE] % coreStatistic.coreName
        ]
        try:
            size, unit = split(coreStatistic.data["solr-mbeans"][3]["/replication"]["stats"]["indexSize"], " ")
            #erase ',' from the size
            cleanSize = size.replace(",", "")
            if unit == "KB":
                sizeInBytes = float(cleanSize) * 1000
            elif unit == "MB":
                sizeInBytes = float(cleanSize) * 1000000
            else:
                sizeInBytes = float(cleanSize)

            ret = self.Metric(SolrMetrics.METRIC_NAME_ENUM.INDEX_SIZE, sizeInBytes, tags)
        except Exception as e:
            self.log.error(("error getting index size for core {}: {}").format(coreStatistic.coreName, e))
            ret = self.Metric(SolrMetrics.METRIC_NAME_ENUM.NONE, 0, None)

        return ret
