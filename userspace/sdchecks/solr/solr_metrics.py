import json
import urllib2
from urlparse import urlparse

from enum import Enum

from utils.network import Network


class SolrMetrics(object):

    class Tag(Enum):
        COLLECTION = 1
        SHARD = 2
        NODE = 3
        REPLICA = 4

    TAG_NAME = {
        Tag.COLLECTION: "solr.tag.collection:%s",
        Tag.REPLICA: "solr.tag.replica:%s",
        Tag.NODE: "solr.tag.node:%s",
        Tag.SHARD: "solr.tag.shard:%s"
    }

    class METRIC_NAME_ENUM(Enum):
        LIVE_NODES = 1,
        SHARDS = 2,
        REPLICA = 3,
        DOCUMENT_COUNT = 4,
        BROWSE_RPS = 5,
        SELECT_RPS = 6,
        GET_RPS = 7,
        QUERY_RPS = 8,
        UPDATE_RPS = 9,
        INDEX_SIZE = 10,
        BROWSE_RT = 11,
        SELECT_RT = 12,
        GET_RT = 13,
        QUERY_RT = 14,
        UPDATE_RT = 15,
        TOTAL_NUMBER_OF_SHARDS = 16

    class Endpoint(Enum):
        LIVE_NODES = 1
        SHARDS = 2
        REPLICA = 3
        DOCUMENT_COUNT = 4
        COLLECTION = 5
        NODE = 6
        CORES_INFO = 7
        VERSION = 8
        STATS = 9

    URL = {
        Endpoint.LIVE_NODES: "/solr/admin/collections?action=clusterstatus&wt=json",
        Endpoint.SHARDS: "/solr/admin/collections?action=clusterstatus&wt=json",
        Endpoint.REPLICA: "/solr/admin/collections?action=clusterstatus&wt=json",
        Endpoint.DOCUMENT_COUNT: "/solr/admin/cores?wt=json"
    }

    class Metric:
        def __init__(self, name, value, tags):
            self.name = name
            self.value = value
            self.tags = tags

        def getValue(self):
            return self.value

        def getTags(self):
            return self.tags

        def getName(self):
            return self.name

    def __init__(self, version, instance):
        self.version = version
        self.instance = instance
        self.ports = instance["ports"]
        self.host = instance["host"]
        self.network = Network()
        self.localCores = set()
        self._findLocalCores()

    def check(self):
        # This should be run just once in a while
        self._findLocalCores()
        allRps, coresStatisticJson = self._getAllRpsAndRequestTime()
        ret = [
            self._getLiveNodes(),
            self._getShards(),
            self._getReplica(),
            self._getDocumentCount(),
            allRps,
            self._getIndexSize(coresStatisticJson)
        ]
        return ret

    def getMajorNumberVersion(self):
        return int(self.version[0:1])

    @staticmethod
    def formatUrl(host, port, handler):
        ret = "http://" + host + ":" + str(port) + handler
        return ret

    @staticmethod
    def getUrl(host, ports, handler):
        found = False
        for port in ports:
            try:
                if found is True:
                    break
                url = SolrMetrics.formatUrl(host, port, handler)
                data = urllib2.urlopen(url)
                obj = json.load(data)
                found = True
            except:
                found = False
        if found is True:
            return obj
        else:
            return {}

    def _getUrl(self, handler):
        return SolrMetrics.getUrl(self.host, self.ports, handler)

    def _getLiveNodes(self):
        ret = []
        obj = self._getUrl(SolrMetrics.URL[SolrMetrics.Endpoint.LIVE_NODES])

        if len(obj) > 0:
            try:
                # Count just this local node
                live_nodes = 0
                for node in obj["cluster"]["live_nodes"]:
                    nodeIp = node[0:node.find(":")]
                    if self.network.ipIsLocalHostOrDockerContainer(nodeIp):
                        live_nodes = live_nodes + 1
                    ret.append(self.Metric(self.METRIC_NAME_ENUM.LIVE_NODES, live_nodes, None))
            except KeyError:
                pass
        return ret

    def _getShards(self):
        # There is no way to send just the localhost shards number
        # Any shard lives in many hosts (differently from replica that lives just in a single host)
        # and so it is impossible to choose which host must count the shard
        # This metric must be intended as Shard Per Collection and MUST NOT be Summed  in the Monitor
        # Separately, the total number of shards is calculated. Also this metric MUST NOT be summed
        class ShardPerNode:
            pass

        ret = []
        obj = self._getUrl(SolrMetrics.URL[SolrMetrics.Endpoint.SHARDS])
        if len(obj) > 0:
            shardPerNodeMap = {}
            totalNumberOfShards = 0
            for collection in obj["cluster"]["collections"]:
                for shard in obj["cluster"]["collections"][collection]["shards"]:
                    totalNumberOfShards = totalNumberOfShards + 1
                    for replica in obj["cluster"]["collections"][collection]["shards"][shard]["replicas"]:
                        nodeName = obj["cluster"]["collections"][collection]["shards"][shard]["replicas"][replica]["node_name"]
                        key = str("{}_{}_{}").format(shard, collection, nodeName)
                        if shardPerNodeMap.has_key(key):
                            shardPerNodeMap[key].count = shardPerNodeMap[key].count + 1
                        else:
                            newShard = ShardPerNode()
                            newShard.key = key
                            newShard.name = shard
                            newShard.collection = collection
                            newShard.node = nodeName
                            newShard.count = 1
                            shardPerNodeMap[key] = newShard

            for shard in shardPerNodeMap:
                tag = [
                    self.TAG_NAME[self.Tag.COLLECTION] % shardPerNodeMap[shard].collection,
                    self.TAG_NAME[self.Tag.NODE] % shardPerNodeMap[shard].node
                ]
                ret.append(self.Metric(self.METRIC_NAME_ENUM.SHARDS, shardPerNodeMap[shard].count, tag))

            ret.append(self.Metric(self.METRIC_NAME_ENUM.TOTAL_NUMBER_OF_SHARDS, totalNumberOfShards, None))
        return ret


    def _getReplica(self):
        class replicaPerNode:
            pass

        ret = []
        obj = self._getUrl(SolrMetrics.URL[SolrMetrics.Endpoint.REPLICA])
        if len(obj) > 0:
            for collection in obj["cluster"]["collections"]:
                for shard in obj["cluster"]["collections"][collection]["shards"]:
                    replicaPerNodeMap = {}
                    for replica in obj["cluster"]["collections"][collection]["shards"][shard]["replicas"]:
                        if obj["cluster"]["collections"][collection]["shards"][shard]["replicas"][replica]["state"] == "active":
                            nodeName = obj["cluster"]["collections"][collection]["shards"][shard]["replicas"][replica]["node_name"]
                            coreAlias = obj["cluster"]["collections"][collection]["shards"][shard]["replicas"][replica]["core"]
                            if coreAlias in self.localCores:
                                if replicaPerNodeMap.has_key(nodeName):
                                    replicaPerNodeMap[nodeName].len = replicaPerNodeMap[nodeName].len + 1
                                else:
                                    newEntry = replicaPerNode()
                                    newEntry.len = 1
                                    newEntry.name = nodeName
                                    newEntry.collection = collection
                                    newEntry.shard = shard
                                    replicaPerNodeMap[nodeName] = newEntry
                    for nodeName in replicaPerNodeMap:
                        tags = [
                            self.TAG_NAME[self.Tag.NODE] % nodeName,
                            self.TAG_NAME[self.Tag.COLLECTION] % replicaPerNodeMap[nodeName].collection,
                            self.TAG_NAME[self.Tag.SHARD] % replicaPerNodeMap[nodeName].shard
                        ]
                        ret.append(self.Metric(self.METRIC_NAME_ENUM.REPLICA, replicaPerNodeMap[nodeName].len, tags))
        return ret

    def _getDocumentCount(self):
        ret = []
        obj = self._getUrl(SolrMetrics.URL[SolrMetrics.Endpoint.DOCUMENT_COUNT])
        if len(obj) > 0:
            for replica_alias in obj["status"]:
                collection = obj["status"][replica_alias]["cloud"]["collection"]
                shard = obj["status"][replica_alias]["cloud"]["shard"]
                replica = obj["status"][replica_alias]["cloud"]["replica"]
                numDocs = obj["status"][replica_alias]["index"]["numDocs"]
                tags = [
                    self.TAG_NAME[self.Tag.COLLECTION] % collection,
                    self.TAG_NAME[self.Tag.SHARD] % shard,
                    self.TAG_NAME[self.Tag.REPLICA] % replica
                ]
                ret.append(self.Metric(self.METRIC_NAME_ENUM.DOCUMENT_COUNT, numDocs, tags))
        return ret

    def _findLocalCores(self):
        obj = self._getUrl(SolrMetrics.URL[SolrMetrics.Endpoint.LIVE_NODES])
        if len(obj) > 0:
            for collection in obj["cluster"]["collections"]:
                for shard in obj["cluster"]["collections"][collection]["shards"]:
                    for core_node in obj["cluster"]["collections"][collection]["shards"][shard]["replicas"]:
                        base_url = obj["cluster"]["collections"][collection]["shards"][shard]["replicas"][core_node]["base_url"]
                        ip_address = urlparse(base_url).hostname
                        if self.network.ipIsLocalHostOrDockerContainer(ip_address):
                            self.localCores.add(obj["cluster"]["collections"][collection]["shards"][shard]["replicas"][core_node]["core"])
