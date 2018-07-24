import json
import logging
import urllib2
import socket
from enum import Enum
from sets import Set
from urlparse import urlparse
from utils.network import Network
from string import split

from checks import AgentCheck, CheckException

class Solr(AgentCheck):
    SOURCE_TYPE_NAME = "solr"

    DEFAULT_TIMEOUT = 5

    TAG_COLLECTION = "solr.collection.name:%s"
    TAG_SHARD = "solr.shard.name:%s"
    TAG_CORE = "solr.core.name:%s"
    TAG_CORE_ALIAS = "solr.core.alias:%s"

    ENDPOINT_CLUSTER = "/solr/admin/collections?action=clusterstatus&wt=json"
    ENDPOINT_LIVE_NODES = ENDPOINT_CLUSTER
    ENDPOINT_SHARDS = ENDPOINT_CLUSTER
    ENDPOINT_REPLICA = ENDPOINT_CLUSTER
    ENDPOINT_COLLECTION = ENDPOINT_CLUSTER
    ENDPOINT_DOCUMENT_COUNT = "/solr/admin/cores?wt=json"
    ENDPOINT_STATS = "/solr/%s/admin/mbeans?stats=true&wt=json"
    ENDPOINT_VERSION = "/solr/admin/info/system?wt=json"

    METRIC_NONE =                           "solr.unknown"
    METRIC_LIVE_NODES =                     "solr.live_nodes"
    METRIC_REPLICA =                        "solr.core_count"
    METRIC_DOCUMENT_COUNT =                 "solr.document_count"
    METRIC_DOCUMENT_COUNT_MAX =             "solr.document_count_max"
    METRIC_DOCUMENT_COUNT_DELETED =         "solr.document_count_deleted"
    METRIC_BROWSE_RPS =                     "solr.browse.requests_per_second"
    METRIC_SELECT_RPS =                     "solr.select.requests_per_second"
    METRIC_GET_RPS =                        "solr.get.requests_per_second"
    METRIC_QUERY_RPS =                      "solr.query.requests_per_second"
    METRIC_UPDATE_RPS =                     "solr.update.requests_per_second"
    METRIC_BROWSE_RT =                      "solr.browse.request_time"
    METRIC_SELECT_RT =                      "solr.select.request_time"
    METRIC_GET_RT =                         "solr.get.request_time"
    METRIC_QUERY_RT =                       "solr.query.request_time"
    METRIC_UPDATE_RT =                      "solr.update.request_time"
    METRIC_INDEX_SIZE_REP =                 "solr.index_size.replicated"
    METRIC_INDEX_SIZE_LOG =                 "solr.index_size.logical"
    METRIC_HOST_SHARD_COUNT =               "solr.host.shard_count"
    METRIC_COLLECTION_SHARD_COUNT =         "solr.collection.shard_count"
    METRIC_UPDATEHANDLER_ADDS =             "solr.updatehandler.adds"
    METRIC_UPDATEHANDLER_DELETES_BY_ID =    "solr.updatehandler.deletes_by_id"
    METRIC_UPDATEHANDLER_DELETES_BY_QUERY = "solr.updatehandler.deletes_by_query"
    METRIC_UPDATEHANDLER_COMMITS =          "solr.updatehandler.commits"
    METRIC_UPDATEHANDLER_AUTOCOMMITS =      "solr.updatehandler.autocommits"

    class Core:
        def __init__(self, name, alias, shard, collection, base_url, port, leader = None):
            self.name = name
            self.alias = alias
            self.shard = shard
            self.collection = collection
            self.base_url = base_url
            self.port = port
            self.leader = leader

        def __hash__(self):
            return ("{}{}{}{}{}").format(self.name, self.alias, self.shard, self.collection, self.base_url).__hash__()

        def __eq__(self, other):
            return self.name == other.name and self.alias == other.alias and self.shard == other.shard and self.collection == other.collection and self.base_url == other.base_url

        def getPort(self):
            return self.port

    class PrevStat:
        def __init__(self, val, time):
            self.val = val
            self.time = time

    def __init__(self, name, init_config, agentConfig, instances=None):
        AgentCheck.__init__(self, name, init_config, agentConfig, instances)
        self.version = None
        self.failed = False
        self.ports = []
        self.port = 0
        self.host = ""
        self.network = Network()
        self.localCores = set()
        self.localLeaderCores = set()
        self.localEndpoints = set()
        self.collectionByCore = dict()
        self.timeout = self.DEFAULT_TIMEOUT
        self.prevStats = dict()
        self.cache = dict()
    
    def clearCache(self):
        self.localCores = set()
        self.localLeaderCores = set()
        self.localEndpoints = set()
        self.collectionByCore = dict()
        self.cache = dict()

    def SolrMetriccheck(self, confTags):
        self.clearCache()

        self.log.debug(str("solr: Start metrics collection: host {}, port {}, ports {}").format(self.host, self.port, self.ports))
        self._retrieveLocalEndpointsAndCores()

        self._getLiveNodes(confTags)
        self._getReplica(confTags)
        self._getLocalDocumentCount(confTags)
        self._getAllRpsAndRequestTime(confTags)
        self._getIndexSize(confTags)
        self._getCollectionShardCount(confTags)
        self._getHostShardCount(confTags)

        self.log.debug(str("solr: End metrics collection"))

    def getMajorNumberVersion(self):
        return int(self.version[0:1])

    def getUrl(self, url):
        if url in self.cache:
            self.log.debug("solr: getting url response from cache: {}".format(url))
            return self.cache.get(url)

        self.log.debug("solr: querying url: {}".format(url))
        try:
            data = urllib2.urlopen(url, None, self.timeout)
            obj = json.load(data)
        except Exception as e:
            self.log.debug(str("solr: error while querying url {}: {}").format(url, e))
            # Cache failures as well, so we don't retry
            self.cache[url] = {}
            return {}

        if obj is None or len(obj) == 0:
            self.log.debug(str("solr: empty response from url {}").format(url))
            self.cache[url] = {}
            return {}

        self.cache[url] = obj
        return obj

    def scanPorts(self, handler):
        ports = [ self.port ] if self.port else self.ports

        self.log.debug("solr: scanPorts: host {} ports {} handler {}".format(self.host, self.ports, handler))
        for port in ports:
            url = "http://" + self.host + ":" + str(port) + handler
            obj = self.getUrl(url)
            if obj is not None and len(obj) > 0:
                self.port = port
                return obj
        return {}

    def getHandler(self, handler):
        url = "http://" + self.host + ":" + str(self.port) + handler
        return self.getUrl(url)

    def getHandlerWithBase(self, baseUrl, handler):
        idx = baseUrl.find('/solr')
        url = (baseUrl + handler) if (idx == -1) else (baseUrl[0:idx] + handler)
        return self.getUrl(url)

    def _isLocal(self, ip, port):
        try:
            ret = self.network.ipIsLocalHostOrDockerContainer(ip) and int(self.port) == int(port)
            self.log.debug("solr: {}:{} is {} to {}:{}".format(ip, port, "local" if ret else "not local", "localhost", self.port))
        except:
            self.log.warning("solr: Failed to determine if {}:{} is local to {}:{}".format(ip, port, "localhost", self.port))
            return False

        return ret

    def _getLiveNodes(self, confTags):
        obj = self.getHandler(self.ENDPOINT_LIVE_NODES)

        if len(obj) > 0:
            try:
                live_node_count = 0
                for live_node in obj["cluster"]["live_nodes"]:
                    hostname = live_node.split(':')[0]
                    port = live_node.split(':')[1].split('_')[0]
                    ip_address = socket.gethostbyname(hostname)
                    if self._isLocal(ip_address, port):
                        live_node_count += 1

                self.gauge(self.METRIC_LIVE_NODES, live_node_count, confTags)
                self.log.debug(("solr: detected {} live local nodes").format(live_node_count))
            except KeyError:
                pass

    def _getCollectionShardCount(self, confTags):
        try:
            obj = self.getHandler(self.ENDPOINT_SHARDS)
            if len(obj) == 0:
                return

            for collection in obj["cluster"]["collections"]:
                shards_per_collection = len(obj["cluster"]["collections"][collection]["shards"])
                tags = confTags + [ self.TAG_COLLECTION % collection ]
                self.gauge(self.METRIC_COLLECTION_SHARD_COUNT, shards_per_collection, tags)
        except Exception as e:
            self.log.error(("solr: Error while fetching collection shard count: {}").format(e))

    def _getHostShardCount(self, confTags):
        try:
            obj = self.getHandler(self.ENDPOINT_SHARDS)
            if len(obj) == 0:
                return

            for collection in obj["cluster"]["collections"]:
                shards_per_host = 0
                shards = obj["cluster"]["collections"][collection]["shards"]

                for shard in shards.values():
                    for replica in shard["replicas"].values():
                        base_url = replica["base_url"]
                        parsedUrl = urlparse(base_url)
                        node_name = parsedUrl.hostname
                        port = parsedUrl.port
                        node_ip_address = socket.gethostbyname(node_name)
                        if self._isLocal(node_ip_address, port):
                            # found a replica that is local to this host
                            shards_per_host = shards_per_host + 1
                            break

                tags = confTags + [ self.TAG_COLLECTION % collection ]
                self.gauge(self.METRIC_HOST_SHARD_COUNT, shards_per_host, tags)
        except Exception as e:
            self.log.error(("solr: Error while fetching host shard count: {}").format(e))

    def _getReplica(self, confTags):
        try:
            obj = self.getHandler(self.ENDPOINT_REPLICA)
            if len(obj) > 0:
                for collectionName, collection in obj["cluster"]["collections"].iteritems():
                    replicaCount = 0
                    for shardName, shard in collection["shards"].iteritems():
                        for coreAlias, replica in shard["replicas"].iteritems():
                            if replica["state"] == "active":
                                nodeName = replica["node_name"]
                                coreName = replica["core"]
                                baseUrl = replica["base_url"]
                                thisCore = self.Core(coreName, coreAlias, shardName, collectionName, baseUrl, urlparse(baseUrl).port)
                                if thisCore in self.localCores:
                                    replicaCount += 1
                    if replicaCount > 0:
                        tags = confTags + [ self.TAG_COLLECTION % collectionName, ]
                        self.gauge(self.METRIC_REPLICA, replicaCount, tags)
                        self.log.debug(("solr: detected {} replicas with tags {}").format(replicaCount, tags))
        except Exception as e:
            self.log.error(("solr: Error while fetching replicas: {}").format(e))

    def _getLocalDocumentCount(self, confTags):
        for base in self.localEndpoints:
            mets = self._getCoreDocumentCount(base, confTags)

    def _getCoreDocumentCount(self, base, confTags):
        try:
            obj = self.getHandlerWithBase(base, self.ENDPOINT_DOCUMENT_COUNT)
            if len(obj) > 0:
                for core_name in obj["status"]:
                    tags = confTags + [ self.TAG_CORE % core_name ]
                    collectionName = self.collectionByCore.get(core_name, None)
                    if collectionName is not None:
                        tags.append(self.TAG_COLLECTION % collectionName)

                    self.log.debug(str("solr: checking document count for core {}").format(core_name))

                    if core_name not in self.localLeaderCores:
                        # Report 0 for non-leader cores so that the number panel in the host specific dashboard has data to show
                        self.gauge(self.METRIC_DOCUMENT_COUNT, 0, tags)
                        self.gauge(self.METRIC_DOCUMENT_COUNT_MAX, 0, tags)
                        self.gauge(self.METRIC_DOCUMENT_COUNT_DELETED, 0, tags)
                        continue

                    self.log.debug(str("solr: fetching document count for local leader core {}").format(core_name))
                    numDocs = obj["status"][core_name]["index"]["numDocs"]
                    maxDoc = obj["status"][core_name]["index"]["maxDoc"]
                    deletedDocs = obj["status"][core_name]["index"]["deletedDocs"]

                    self.gauge(self.METRIC_DOCUMENT_COUNT, numDocs, tags)
                    self.gauge(self.METRIC_DOCUMENT_COUNT_MAX, maxDoc, tags)
                    self.gauge(self.METRIC_DOCUMENT_COUNT_DELETED, deletedDocs, tags)
        except Exception as e:
            self.log.error(("solr: Error while fetching document count from {}: {}").format(base, e))

    def _retrieveLocalEndpointsAndCores(self):
        obj = self.getHandler(self.ENDPOINT_LIVE_NODES)
        if len(obj) > 0:
            try:
                for collectionName, collection in obj["cluster"]["collections"].iteritems():
                    for shardName, shard in collection["shards"].iteritems():
                        for coreAlias, replica in shard["replicas"].iteritems():
                            if replica["state"] != "active":
                                self.log.debug(("solr: Skipping core {}_{}_{} in state {} on node {}").format(collectionName, shardName, coreAlias, replica["state"], replica["base_url"]))
                                continue
                            base_url = replica["base_url"]
                            parsedUrl = urlparse(base_url)
                            hostname_from_url = parsedUrl.hostname
                            port_from_url = parsedUrl.port
                            ip_address = socket.gethostbyname(hostname_from_url)
                            if self._isLocal(ip_address, port_from_url):
                                coreName = replica["core"]

                                leader = replica.get("leader", False)
                                if bool(leader):
                                    self.localLeaderCores.add(coreName)

                                self.collectionByCore[coreName] = collectionName
                                self.localCores.add(self.Core(coreName, coreAlias, shardName, collectionName, base_url, port_from_url))
                                # Since we're matching both ip and port
                                # localEndpoints should only have one base_url
                                self.localEndpoints.add(base_url)
                                self.log.debug(str("solr: detected local core {}:{} on node {}").format(coreName, coreAlias, base_url))
            except Exception as e:
                self.log.error(("solr: Error while attempting to fetch local cores: {}").format(e))

    def _getAllRpsAndRequestTime(self, confTags):
        coresStatistic = self._getStats()
        self.log.debug(str("solr: fetching rps+rt metrics for {} local cores").format(len(coresStatistic)))
        for coreStat in coresStatistic:
            self.log.debug(str("solr: fetching rps+rt metrics for local core: {}.{}").format(coreStat.core.name, coreStat.core.alias))
            # create tags here
            collection = coreStat.core.collection
            coreName = coreStat.core.name
            coreAlias = coreStat.core.alias
            tags = confTags + [
                self.TAG_COLLECTION % collection,
                self.TAG_CORE % coreName,
                self.TAG_CORE_ALIAS % coreAlias,
            ]

            self._getFromCoreRpsAndRequestTime(coreStat.data, tags)
            self._getUpdateHandlerStats(coreStat.data, tags)

    def _getIndexSize(self, confTags):
        coresStatisticJson = self._getStats()
        for coreStatistic in coresStatisticJson:
            self._getFromCoreIndexSize(coreStatistic, confTags)

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
        return self.getHandlerWithBase(base, self.ENDPOINT_STATS % corename)

    def _getFromCoreRpsAndRequestTime(self, obj, tags):

        # in solr 5, a map has been implemented as an array in which
        # first is put the key, and then the value
        try:
            beans = obj["solr-mbeans"]
            assert beans[2] == "QUERYHANDLER"
            queryHandlerObj = beans[3]

            self._getSingleRps(self.METRIC_BROWSE_RPS, "/browse", queryHandlerObj, tags)
            self._getSingleRps(self.METRIC_SELECT_RPS, "/select", queryHandlerObj, tags)
            self._getSingleRps(self.METRIC_GET_RPS, "/get", queryHandlerObj, tags)
            self._getSingleRps(self.METRIC_QUERY_RPS, "/query", queryHandlerObj, tags)
            self._getSingleRps(self.METRIC_UPDATE_RPS, "/update", queryHandlerObj, tags)

            self._getSingleRequestTime(self.METRIC_BROWSE_RT, "/browse", queryHandlerObj, tags)
            self._getSingleRequestTime(self.METRIC_SELECT_RT, "/select", queryHandlerObj, tags)
            self._getSingleRequestTime(self.METRIC_GET_RT, "/get", queryHandlerObj, tags)
            self._getSingleRequestTime(self.METRIC_QUERY_RT, "/query", queryHandlerObj, tags)
            self._getSingleRequestTime(self.METRIC_UPDATE_RT, "/update", queryHandlerObj, tags)
        except Exception as e:
            self.log.debug(("solr: unable to get rps+rt metrics for local core: {}").format(e))

    def _getSingleRps(self, metricName, keyString, queryHandlerObj, tags):
        try:
            self.rate(metricName, queryHandlerObj[keyString]["stats"]["requests"], tags)
        except Exception as e:
            self.log.debug(("solr: could not get rps {} {}: {}").format(metricName, keyString, e))

    def _getSingleRequestTime(self, metricName, keyString, queryHandlerObj, tags):
        try:
            reqs = int(queryHandlerObj[keyString]["stats"]["requests"])
            tottime = float(queryHandlerObj[keyString]["stats"]["totalTime"])
        except Exception as e:
            self.log.debug(("solr: could not get request time {} {}: {}").format(metricName, keyString, e))

        key = tuple(tags) + (("type:%s" % keyString), )
        prevStats = self.prevStats.get(key, None)
        if prevStats is not None:
            dreqs = reqs - prevStats.val
            dtime = tottime - prevStats.time
            if dreqs > 0 and dtime > 0:
                self.gauge(metricName, float(dtime / dreqs), tags)
            elif dreqs < 0 or dtime < 0:
                self.log.debug("solr: decreased request count or total time, resetting stored stats for {}".format(key))
            elif dreqs != 0 or dtime != 0:
                self.log.info("solr: request time/count inconsistent: {}/{} for {}".format(dtime, dreqs, key))
        else:
            self.log.debug("solr: Previous req stats not found for {}".format(key))

        self.prevStats[key] = self.PrevStat(reqs, tottime)

    def _getUpdateHandlerStats(self, obj, tags):
        try:
            beans = obj["solr-mbeans"]
            assert beans[4] == "UPDATEHANDLER"
            stats = beans[5]

            self.rate(self.METRIC_UPDATEHANDLER_ADDS, long(stats["updateHandler"]["stats"]["cumulative_adds"]), tags)
            self.rate(self.METRIC_UPDATEHANDLER_DELETES_BY_ID, long(stats["updateHandler"]["stats"]["cumulative_deletesById"]), tags)
            self.rate(self.METRIC_UPDATEHANDLER_DELETES_BY_QUERY, long(stats["updateHandler"]["stats"]["cumulative_deletesByQuery"]), tags)
            self.rate(self.METRIC_UPDATEHANDLER_COMMITS, long(stats["updateHandler"]["stats"]["commits"]), tags)
            self.rate(self.METRIC_UPDATEHANDLER_AUTOCOMMITS, long(stats["updateHandler"]["stats"]["autocommits"]), tags)
        except Exception as e:
            self.log.debug(("solr: unable to get updatehandler stats: {}").format(e))

    # It is assumed that this implementation must always find index size.
    # Failure to find the metric is logged as an error.
    def _getFromCoreIndexSize(self, coreStatistic, confTags):
        if coreStatistic.data is None or len(coreStatistic.data) == 0:
            self.log.debug(str("solr: Unable to get index size from empty stats for core: {}").format(coreStatistic.core.name))
            return

        tags = confTags + [
            self.TAG_COLLECTION % coreStatistic.core.collection,
            self.TAG_CORE % coreStatistic.core.name,
            self.TAG_CORE_ALIAS % coreStatistic.core.alias,
        ]

        try:
            beans = coreStatistic.data["solr-mbeans"]
            if beans[0] != "CORE":
                raise Exception('solr: CORE not in position 0 in solr-mbeans')
            if beans[2] != "QUERYHANDLER":
                raise Exception('solr: QUERYHANDLER not in position 2 in solr-mbeans')

            handlers = beans[3]
            if '/replication' in handlers:
                indexSize = handlers["/replication"]["stats"]["indexSize"]
                self.log.debug(str("solr: index size retrieved from /replication for core {}: {}").format(coreStatistic.core.name, indexSize))

                val, unit = indexSize.split()

                # See lucene-solr/solr/core/src/java/org/apache/solr/utils/NumberUtils.java
                if unit.lower() == "gb":
                    valInBytes = float(val) * 1024 * 1024 * 1024
                elif unit.lower() == "mb":
                    valInBytes = float(val) * 1024 * 1024
                elif unit.lower() == "kb":
                    valInBytes = float(val) * 1024
                elif unit.lower() == "bytes":
                    valInBytes = long(val)
            else:
                indexSize = beans[1]["core"]["stats"]["sizeInBytes"]
                self.log.debug(str("solr: index size retrieved from core stats for core {}: {}").format(coreStatistic.core.name, indexSize))
                valInBytes = long(indexSize)

            self.gauge(self.METRIC_INDEX_SIZE_REP, valInBytes, tags)
            # Report 0 for non-leader cores for logical size so we still show data for the core but
            # the total of all cores still shows the correct size for the collection
            logicalSize = valInBytes if coreStatistic.core.name in self.localLeaderCores else 0
            self.gauge(self.METRIC_INDEX_SIZE_LOG, logicalSize, tags)
        except Exception as e:
            self.log.error(("solr: Error getting index size for core {}: {}").format(coreStatistic.core.name, e))

    def check(self, instance):
        # Don't waste time retrying if we failed because of bad version
        if self.failed:
            return

        if self.version is None:
            self.host = instance["host"]
            self.ports = instance["ports"]
            self.port = instance.get("solr_port", 0)

            if self.port == 0 and len(self.ports) == 0:
                self.log.info("Cannot proceed without a supplied port. Config is {}".format(instance))
                return

            self._getSolrVersion(instance)

            if self.version is None:
                # Default retry behavior is managed by config and sdchecks.py
                # We might have more luck next time?
                raise CheckException("solr: Failed to determine version. Config is {}".format(instance))
            elif self.version[0:1] != "5":
                # Don't retry, cause we would always end up here.
                self.failed = True
                raise CheckException("solr: Version {} not yet supported".format(self.version[0:1]))

        confTags = instance.get('tags', [])
        self.SolrMetriccheck(confTags)

    def _getSolrVersion(self, instance):
        if self.version == None:
            self.log.debug("solr: getting version from ports {}, endpoint {}".format(instance["ports"], self.ENDPOINT_VERSION))
            obj = self.scanPorts(self.ENDPOINT_VERSION)
            self.log.debug("solr: version check at port {} returned {}".format(self.port, obj))
            if len(obj) > 0:
                self.log.debug(str("solr: version endpoint found on port {} out of ports {}").format(self.port, instance["ports"]))
                self.version = obj["lucene"]["solr-spec-version"]
                assert int(self.version[0:1]) >= 4

