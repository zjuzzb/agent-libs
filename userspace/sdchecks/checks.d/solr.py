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

    def SolrMetric__init__(self, version, instance):
        self.version = version
        self.instance = instance
        self.ports = instance["ports"]
        self.port = 0
        self.host = instance["host"]
        self.network = Network()
        self.localCores = set()
        self.localLeaderCores = set()
        self.localEndpoints = set()
        self.collectionByCore = dict()
        self.log = logging.getLogger(__name__)
        self.timeout = self.DEFAULT_TIMEOUT
    
    def clearCache(self):
        self.localCores = set()
        self.localLeaderCores = set()
        self.localEndpoints = set()
        self.collectionByCore = dict()
#        self.clusterStats = None
#        self.coreStats = None

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

    @staticmethod
    def formatUrl(host, port, handler):
        ret = "http://" + host + ":" + str(port) + handler
        return ret

    @staticmethod
    def getUrl2(host, ports, handler, log):
        log.debug("Solr.getUrl2: host {} handler {}".format(host, handler))
        found = False
        foundPort = 0
        timeout = Solr.DEFAULT_TIMEOUT
        log.debug("Solr, trying ports: {}, timeout {}".format(ports, timeout))
        for port in ports:
            log.debug("Solr.getUrl2: port {}".format(port))
            url = "http://" + host + ":" + str(port) + handler
            log.debug("Solr, trying url: {}".format(url))
            try:
                if found is True:
                    break
                # url = formatUrl(host, port, handler)
                data = urllib2.urlopen(url, None, timeout)
                obj = json.load(data)
                found = True
                foundPort = port
            except:
                found = False
        if found is True:
            return [obj, foundPort]
        else:
            return [{}, 0]

    def _getUrl(self, handler):
        ports = [ self.port ] if self.port else self.ports
        obj, self.port = self.getUrl2(self.host, ports, handler, self.log)
        return obj

    def _getUrlWithBase(self, baseUrl, handler):
        url = str("{}{}").format(baseUrl[0:baseUrl.find('/solr')], handler)
        try:
            self.log.debug("Solr, getting url: {}".format(url))
            data = urllib2.urlopen(url, None, self.timeout)
            obj = json.load(data)
        except:
            return {}

        return obj

    def _isLocal(self, ip, port):
        try:
            ret = self.network.ipIsLocalHostOrDockerContainer(ip) and int(self.port) == int(port)
            self.log.debug("{}:{} is {} to {}:{}".format(ip, port, "local" if ret else "not local", "localhost", self.port))
        except:
            self.log.warning("Failed to determine locality of {}:{} on {}:{}".format(ip, port, "localhost", self.port))
            return False

        return ret

    def _getLiveNodes(self, confTags):
        obj = self._getUrl(self.ENDPOINT_LIVE_NODES)

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
                self.log.debug(("detected {} live local nodes").format(live_node_count))
            except KeyError:
                pass

    def _getCollectionShardCount(self, confTags):
        try:
            obj = self._getUrl(self.ENDPOINT_SHARDS)
            if len(obj) == 0:
                return

            for collection in obj["cluster"]["collections"]:
                shards_per_collection = len(obj["cluster"]["collections"][collection]["shards"])
                tags = confTags + [ self.TAG_COLLECTION % collection ]
                self.gauge(self.METRIC_COLLECTION_SHARD_COUNT, shards_per_collection, tags)
        except Exception as e:
            self.log.error(("Error while fetching collection shard count: {}").format(e))

    def _getHostShardCount(self, confTags):
        try:
            obj = self._getUrl(self.ENDPOINT_SHARDS)
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
            self.log.error(("Error while fetching host shard count: {}").format(e))

    def _getReplica(self, confTags):
        try:
            obj = self._getUrl(self.ENDPOINT_REPLICA)
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
                        self.log.debug(("detected {} replica with tags {}").format(replicaCount, tags))
        except Exception as e:
            self.log.error(("Error while fetching replica: {}").format(e))

    def _getLocalDocumentCount(self, confTags):
        for base in self.localEndpoints:
            mets = self._getCoreDocumentCount(base, confTags)

    def _getCoreDocumentCount(self, base, confTags):
        try:
            obj = self._getUrlWithBase(base, self.ENDPOINT_DOCUMENT_COUNT)
            if len(obj) > 0:
                for core_name in obj["status"]:
                    tags = confTags + [ self.TAG_CORE % core_name ]
                    collectionName = self.collectionByCore.get(core_name, None)
                    if collectionName is not None:
                        tags.append(self.TAG_COLLECTION % collectionName)

                    if core_name not in self.localLeaderCores:
                        # Report 0 for non-leader cores so that the number panel in the host specific dashboard has data to show
                        self.gauge(self.METRIC_DOCUMENT_COUNT, 0, tags)
                        self.gauge(self.METRIC_DOCUMENT_COUNT_MAX, 0, tags)
                        self.gauge(self.METRIC_DOCUMENT_COUNT_DELETED, 0, tags)
                        continue

                    numDocs = obj["status"][core_name]["index"]["numDocs"]
                    maxDoc = obj["status"][core_name]["index"]["maxDoc"]
                    deletedDocs = obj["status"][core_name]["index"]["deletedDocs"]

                    self.gauge(self.METRIC_DOCUMENT_COUNT, numDocs, tags)
                    self.gauge(self.METRIC_DOCUMENT_COUNT_MAX, maxDoc, tags)
                    self.gauge(self.METRIC_DOCUMENT_COUNT_DELETED, deletedDocs, tags)
        except Exception as e:
            self.log.error(("Error while fetching core document count: {}").format(e))

    def _retrieveLocalEndpointsAndCores(self):
        obj = self._getUrl(self.ENDPOINT_LIVE_NODES)
        if len(obj) > 0:
            try:
                for collectionName, collection in obj["cluster"]["collections"].iteritems():
                    for shardName, shard in collection["shards"].iteritems():
                        for coreAlias, replica in shard["replicas"].iteritems():
                            if replica["state"] != "active":
                                self.log.debug(("Skipping core {}_{}_{} in state {} on node {}").format(collectionName, shardName, coreAlias, replica["state"], replica["base_url"]))
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
                                self.localEndpoints.add(base_url)
                                self.log.debug(str("detected local core {}:{} on node {}").format(coreName, coreAlias, base_url))
            except Exception as e:
                self.log.error(("Error while attempting to fetch local cores: {}").format(e))

    class PrevStat:
        def __init__(self, val, time):
            self.val = val
            self.time = time

    def Solr5__init__(self, version, instance):
        self.SolrMetric__init__(version, instance)
        self.prevStats = dict()

    def _getAllRpsAndRequestTime(self, confTags):
        coresStatistic = self._getStats()
        self.log.debug(str("fetching statistics for {} local cores").format(len(coresStatistic)))
        for coreStat in coresStatistic:
            self.log.debug(str("fetching statistics for local core: {}.{}").format(coreStat.core.name, coreStat.core.alias))
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
        self.log.debug(str("fetching index memory size for {} local cores").format(len(coresStatisticJson)))
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
        return self._getUrlWithBase(base, self.ENDPOINT_STATS % corename)

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
            self.log.debug(("could not get statistic from local core: {}").format(e))

    def _getSingleRps(self, metricName, keyString, queryHandlerObj, tags):
        try:
            self.rate(metricName, queryHandlerObj[keyString]["stats"]["requests"], tags)
        except Exception as e:
            self.log.debug(("could not get rps {} {}: {}").format(metricEnumValue, keyString, e))

    def _getSingleRequestTime(self, metricName, keyString, queryHandlerObj, tags):
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
                self.gauge(metricEnumValue, float(dtime / dreqs), tags)
            elif dreqs < 0 or dtime < 0:
                self.log.debug("decreased request count or total time, resetting stored stats for {}".format(key))
            elif dreqs != 0 or dtime != 0:
                self.log.info("solr: request time/count inconsistent: {}/{} for {}".format(dtime, dreqs, key))
        else:
            self.log.debug("Previous req stats not found for {}".format(key))

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
            self.log.debug(("unable to get updatehandler stats: {}").format(e))

    def _getFromCoreIndexSize(self, coreStatistic, confTags):
        tags = confTags + [
            self.TAG_COLLECTION % coreStatistic.core.collection,
            self.TAG_CORE % coreStatistic.core.name,
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

            self.gauge(self.METRIC_INDEX_SIZE_REP, sizeInBytes, tags)
            # Report 0 for non-leader cores for logical size so we still show data for the core but
            # the total of all cores still shows the correct size for the collection
            logicalSize = sizeInBytes if coreStatistic.core.name in self.localLeaderCores else 0
            self.gauge(self.METRIC_INDEX_SIZE_LOG, logicalSize, tags)
        except Exception as e:
            self.log.error(("error getting index size for core {}: {}").format(coreStatistic.core.name, e))

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
#                self.sMetric = Solr5(self.version, instance)
                self.sMetric = True
                self.Solr5__init__(self.version, instance)
            elif self.version is None:
                raise CheckException("Failed to find Solr version")
            else:
                raise CheckException("Solr version {} not yet supported".format(self.version[0:1]))

        confTags = instance.get('tags', [])

        self.SolrMetriccheck(confTags)

    def _getSolrVersion(self, instance):
        if self.version == None:
            self.log.debug("Solr, getting version from ports {}, endpoint {}".format(instance["ports"], self.GET_VERSION_ENDPOINT))
            obj, port = self.getUrl2(instance["host"], instance["ports"], self.GET_VERSION_ENDPOINT, self.log)
            self.log.debug("Solr, version check (port {}) returns: {}".format(port, obj))
            if len(obj) > 0:
                self.log.debug(str("solr: version endpoint found on port {} out of ports {}").format(port, instance["ports"]))
                self.version = obj["lucene"]["solr-spec-version"]
                assert int(self.version[0:1]) >= 4

