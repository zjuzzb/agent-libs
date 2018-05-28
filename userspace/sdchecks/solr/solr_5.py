from string import split

from enum import Enum

from solr.solr_metrics import SolrMetrics


class Solr5(SolrMetrics):

    URL = {
        SolrMetrics.Endpoint.CORES_INFO: "/solr/admin/cores?wt=json",
        SolrMetrics.Endpoint.DOCUMENT_COUNT: "/solr/admin/cores?wt=json",
        SolrMetrics.Endpoint.STATS: "/solr/%s/admin/mbeans?stats=true&wt=json"
    }

    class PrevStat:
        def __init__(self, reqs, time):
            self.reqs = reqs
            self.time = time

    class ShardDocumentCount:
        def __init__(self, collection, shard):
            self.collection = collection
            self.shard = shard

        def __hash__(self):
            return str("{}{}").format(self.collection, self.shard).__hash__()

        def __eq__(self, other):
            return (self.collection == other.collection) and (self.shard == other.shard)

    def __init__(self, version, instance):
        SolrMetrics.__init__(self, version, instance)
        self.prevStats = dict()

    def _getNodeDocumentCount(self, node, shardDocumentCountMap):
        endpoint = str("http://{}").format(node.replace("_", "/"))
        obj = self._getUrlWithBase(endpoint, self.URL[SolrMetrics.Endpoint.DOCUMENT_COUNT])
        if len(obj) > 0:
            for core in obj["status"]:
                collection, shard, replica = core.split("_")
                entry = self.ShardDocumentCount(collection, shard)
                if entry not in shardDocumentCountMap:
                    entry.value = obj["status"][core]["index"]["numDocs"]
                    shardDocumentCountMap.add(entry)

    def _getAllRpsAndRequestTime(self):
        ret = []
        coresStatistic = self._getStats()
        self.log.debug(str("fetching statistics for {} local cores").format(len(coresStatistic)))
        for coreStat in coresStatistic:
            self.log.debug(str("fetching statistics for local core: {}.{}").format(coreStat.core.name, coreStat.core.alias))
            # create tags here
            collection = coreStat.core.collection
            coreName = coreStat.core.name
            coreAlias = coreStat.core.alias
            tags = [
                self.TAG_NAME[self.Tag.COLLECTION] % collection,
                self.TAG_NAME[self.Tag.CORE] % coreName,
                self.TAG_NAME[self.Tag.CORE_ALIAS] % coreAlias,
            ]

            all_rps = self._getFromCoreRpsAndRequestTime(coreStat.data, tags)
            # Should just add the tags in getfromCoreRpsAndRequestTime()
            for rps in all_rps:
                rps.tags = tags
                ret.append(rps)

            updateHandlerStats = self._getUpdateHandlerStats(coreStat.data)
            for uhs in updateHandlerStats:
                uhs.tags = tags
                ret.append(uhs)
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
        for core in self.localCores:
            element = CoreStat()
            element.core = core
            element.data = self._getSingleCoreStats(self._generateUrl(core.name))
            ret.append(element)
        return ret

    def _generateUrl(self, core):
        return self.URL[SolrMetrics.Endpoint.STATS] % core

    def _getSingleCoreStats(self, url):
        return self._getUrl(url)

    def _getFromCoreRpsAndRequestTime(self, obj, tags):
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

            arr.extend(self._getSingleCurrentRequestTime(SolrMetrics.METRIC_NAME_ENUM.BROWSE_CRT, "/browse", queryHandlerObj, tags))
            arr.extend(self._getSingleCurrentRequestTime(SolrMetrics.METRIC_NAME_ENUM.SELECT_CRT, "/select", queryHandlerObj, tags))
            arr.extend(self._getSingleCurrentRequestTime(SolrMetrics.METRIC_NAME_ENUM.GET_CRT, "/get", queryHandlerObj, tags))
            arr.extend(self._getSingleCurrentRequestTime(SolrMetrics.METRIC_NAME_ENUM.QUERY_CRT, "/query", queryHandlerObj, tags))
            arr.extend(self._getSingleCurrentRequestTime(SolrMetrics.METRIC_NAME_ENUM.UPDATE_CRT, "/update", queryHandlerObj, tags))
        except Exception as e:
            self.log.debug(("could not get statistic from local core: {}").format(e))
        return arr

    def _getSingleRps(self, metricEnumValue, keyString, queryHandlerObj):
        try:
            ret =  SolrMetrics.Metric(metricEnumValue, queryHandlerObj[keyString]["stats"]["requests"], None, None)
            ret.metricType = SolrMetrics.Metric.MetricType.rate
            return ret
        except Exception as e:
            self.log.debug(("could not get rps {} {}: {}").format(metricEnumValue, keyString, e))
            return SolrMetrics.Metric(SolrMetrics.METRIC_NAME_ENUM.NONE, 0, None, None)

    def _getSingleRequestTime(self, metricEnumValue, keyString, queryHandlerObj):
        try:
            ret = self.Metric(metricEnumValue, float(queryHandlerObj[keyString]["stats"]["avgTimePerRequest"]), None, None)
            ret.metricType = SolrMetrics.Metric.MetricType.gauge
            return ret
        except Exception as e:
            self.log.debug(("could not get request time {} {}: {}").format(metricEnumValue, keyString, e))
            return SolrMetrics.Metric(SolrMetrics.METRIC_NAME_ENUM.NONE, 0, None, None)

    def _getSingleCurrentRequestTime(self, metricEnumValue, keyString, queryHandlerObj, tags):
        ret = []
        try:
            reqs = int(queryHandlerObj[keyString]["stats"]["requests"])
            tottime = float(queryHandlerObj[keyString]["stats"]["totalTime"])
        except Exception as e:
            self.log.debug(("could not get request time {} {}: {}").format(metricEnumValue, keyString, e))

        key = tuple(tags) + (("type:%s" % keyString), )
        prevStats = self.prevStats.get(key, None)
        if prevStats is not None:
            dreqs = reqs - prevStats.reqs
            dtime = tottime - prevStats.time
            if dreqs > 0 and dtime > 0:
                ret.append(self.Metric(metricEnumValue, float(dtime / dreqs), tags, SolrMetrics.Metric.MetricType.gauge))
            elif dreqs < 0 or dtime < 0:
                self.log.debug("inconsistent request count or total time, resetting stored stats for {}".format(key))
        else:
            self.log.debug("Previous req stats not found for {}".format(key))

        self.prevStats[key] = self.PrevStat(reqs, tottime)
        return ret

    # The cumulative_* counts can either increase or decrease and are maintained for the lifetime of
    # Solr. For example, cumulative_adds is incremented when an "add" command is executed and
    # decremented when "rollback" is executed.
    #
    # adds and deletes are point in time values between commits and should be monotonic
    def _getUpdateHandlerStats(self, obj):
        ret = []
        try:
            beans = obj["solr-mbeans"]
            assert beans[4] == "UPDATEHANDLER"
            stats = beans[5]

            metric_adds = SolrMetrics.Metric(SolrMetrics.METRIC_NAME_ENUM.UPDATEHANDLER_ADDS, long(stats["updateHandler"]["stats"]["adds"]), None, None)
            metric_adds.metricType = SolrMetrics.Metric.MetricType.gauge
            ret.append(metric_adds)

            metric_del_id = SolrMetrics.Metric(SolrMetrics.METRIC_NAME_ENUM.UPDATEHANDLER_DELETES_BY_ID, long(stats["updateHandler"]["stats"]["deletesById"]), None, None)
            metric_del_id.metricType = SolrMetrics.Metric.MetricType.gauge
            ret.append(metric_del_id)

            metric_del_q = SolrMetrics.Metric(SolrMetrics.METRIC_NAME_ENUM.UPDATEHANDLER_DELETES_BY_QUERY, long(stats["updateHandler"]["stats"]["deletesByQuery"]), None, None)
            metric_del_q.metricType = SolrMetrics.Metric.MetricType.gauge
            ret.append(metric_del_q)

            metric_commit = SolrMetrics.Metric(SolrMetrics.METRIC_NAME_ENUM.UPDATEHANDLER_COMMITS, long(stats["updateHandler"]["stats"]["commits"]), None, None)
            metric_commit.metricType = SolrMetrics.Metric.MetricType.rate
            ret.append(metric_commit)

            metric_acommit = SolrMetrics.Metric(SolrMetrics.METRIC_NAME_ENUM.UPDATEHANDLER_AUTOCOMMITS, long(stats["updateHandler"]["stats"]["autocommits"]), None, None)
            metric_acommit.metricType = SolrMetrics.Metric.MetricType.rate
            ret.append(metric_acommit)

            return ret
        except Exception as e:
            self.log.error(("unable to get updatehandler stats: {}").format(e))
            return ret

    def _getFromCoreIndexSize(self, coreStatistic):
        tags = [
            self.TAG_NAME[self.Tag.COLLECTION] % coreStatistic.core.collection,
            self.TAG_NAME[self.Tag.CORE] % coreStatistic.core.name,
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
            self.log.error(("error getting index size for core {}: {}").format(coreStatistic.core.name, e))
            ret = self.Metric(SolrMetrics.METRIC_NAME_ENUM.NONE, 0, None)

        return ret
