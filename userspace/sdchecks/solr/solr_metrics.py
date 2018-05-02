import json
import urllib2
from enum import Enum


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
        INDEX_SIZE = 10

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

    def check(self):
        allRps, coresStatisticJson = self._getAllRps()
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
                ret.append(self.Metric(self.METRIC_NAME_ENUM.LIVE_NODES, len(obj["cluster"]["live_nodes"]), None))
            except KeyError:
                pass
        return ret

    def _getShards(self):
        ret = []
        obj = self._getUrl(SolrMetrics.URL[SolrMetrics.Endpoint.SHARDS])
        if len(obj) > 0:
            for collection in obj["cluster"]["collections"]:
                numShards = len(obj["cluster"]["collections"][collection]["shards"])
                assert isinstance(collection, object)
                tag = [self.TAG_NAME[self.Tag.COLLECTION] % collection]
                ret.append(self.Metric(self.METRIC_NAME_ENUM.SHARDS, numShards, tag))
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
