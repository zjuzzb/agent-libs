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
        def __init__(self, val, time):
            self.val = val
            self.time = time

    def __init__(self, version, instance):
        SolrMetrics.__init__(self, version, instance)
        self.prevStats = dict()

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

            updateHandlerStats = self._getUpdateHandlerStats(coreStat.data, tags)
            ret.extend(updateHandlerStats)
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
            element.data = self._getSingleCoreStats(core.base_url, core.name)
            ret.append(element)
        return ret

    def _getSingleCoreStats(self, base, corename):
        return self._getUrlWithBase(base, self.URL[SolrMetrics.Endpoint.STATS] % corename)

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

            arr.extend(self._getSingleRequestTime(SolrMetrics.METRIC_NAME_ENUM.BROWSE_RT, "/browse", queryHandlerObj, tags))
            arr.extend(self._getSingleRequestTime(SolrMetrics.METRIC_NAME_ENUM.SELECT_RT, "/select", queryHandlerObj, tags))
            arr.extend(self._getSingleRequestTime(SolrMetrics.METRIC_NAME_ENUM.GET_RT, "/get", queryHandlerObj, tags))
            arr.extend(self._getSingleRequestTime(SolrMetrics.METRIC_NAME_ENUM.QUERY_RT, "/query", queryHandlerObj, tags))
            arr.extend(self._getSingleRequestTime(SolrMetrics.METRIC_NAME_ENUM.UPDATE_RT, "/update", queryHandlerObj, tags))
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

    def _getSingleRequestTime(self, metricEnumValue, keyString, queryHandlerObj, tags):
        ret = []
        try:
            reqs = int(queryHandlerObj[keyString]["stats"]["requests"])
            tottime = float(queryHandlerObj[keyString]["stats"]["totalTime"])
        except Exception as e:
            self.log.debug(("could not get request time {} {}: {}").format(metricEnumValue, keyString, e))

        key = tuple(tags) + (("type:%s" % keyString), )
        prevStats = self.prevStats.get(key, None)
        if prevStats is not None:
            dreqs = reqs - prevStats.val
            dtime = tottime - prevStats.time
            if dreqs > 0 and dtime > 0:
                ret.append(self.Metric(metricEnumValue, float(dtime / dreqs), tags, SolrMetrics.Metric.MetricType.gauge))
            elif dreqs < 0 or dtime < 0:
                self.log.debug("decreased request count or total time, resetting stored stats for {}".format(key))
            elif dreqs != 0 or dtime != 0:
                self.log.info("solr: request time/count inconsistent: {}/{} for {}".format(dtime, dreqs, key))
        else:
            self.log.debug("Previous req stats not found for {}".format(key))

        self.prevStats[key] = self.PrevStat(reqs, tottime)
        return ret

    def _getUpdateHandlerStats(self, obj, tags):
        ret = []
        try:
            beans = obj["solr-mbeans"]
            assert beans[4] == "UPDATEHANDLER"
            stats = beans[5]

            ret.append(SolrMetrics.Metric(SolrMetrics.METRIC_NAME_ENUM.UPDATEHANDLER_ADDS, long(stats["updateHandler"]["stats"]["cumulative_adds"]), tags, SolrMetrics.Metric.MetricType.rate))
            ret.append(SolrMetrics.Metric(SolrMetrics.METRIC_NAME_ENUM.UPDATEHANDLER_DELETES_BY_ID, long(stats["updateHandler"]["stats"]["cumulative_deletesById"]), tags, SolrMetrics.Metric.MetricType.rate))
            ret.append(SolrMetrics.Metric(SolrMetrics.METRIC_NAME_ENUM.UPDATEHANDLER_DELETES_BY_QUERY, long(stats["updateHandler"]["stats"]["cumulative_deletesByQuery"]), tags, SolrMetrics.Metric.MetricType.rate))
            ret.append(SolrMetrics.Metric(SolrMetrics.METRIC_NAME_ENUM.UPDATEHANDLER_COMMITS, long(stats["updateHandler"]["stats"]["commits"]), tags, SolrMetrics.Metric.MetricType.rate))
            ret.append(SolrMetrics.Metric(SolrMetrics.METRIC_NAME_ENUM.UPDATEHANDLER_AUTOCOMMITS, long(stats["updateHandler"]["stats"]["autocommits"]), tags, SolrMetrics.Metric.MetricType.rate))
        except Exception as e:
            self.log.debug(("unable to get updatehandler stats: {}").format(e))
        return ret

    def _getFromCoreIndexSize(self, coreStatistic):
        tags = [
            self.TAG_NAME[self.Tag.COLLECTION] % coreStatistic.core.collection,
            self.TAG_NAME[self.Tag.CORE] % coreStatistic.core.name,
        ]
        # Report 0 for non-leader cores so we still show data for the core but
        # the total of all cores still shows the correct size for the collection
        if coreStatistic.core.name not in self.localLeaderCores:
            ret = self.Metric(SolrMetrics.METRIC_NAME_ENUM.INDEX_SIZE, 0, tags)
            return ret

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
