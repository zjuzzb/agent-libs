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
        Tag.COLLECTION: "solr.collection:%s",
        Tag.REPLICA: "solr.replica:%s",
        Tag.NODE: "solr.node:%s",
        Tag.SHARD: "solr.shard:%s"
    }

    class METRIC_NAME_ENUM(Enum):
        LIVE_NODES = 1,
        SHARDS = 2,
        REPLICA = 3,
        DOCUMENT_COUNT =4

    class Endpoint(Enum):
        LIVE_NODES = 1
        SHARDS = 2
        REPLICA = 3
        DOCUMENT_COUNT = 4
        COLLECTION = 5
        NODE = 6
        CORES_INFO = 7
        VERSION = 8

    URL = {
        Endpoint.LIVE_NODES: "/solr/admin/collections?action=clusterstatus&wt=json",
        Endpoint.SHARDS: "/solr/admin/collections?action=clusterstatus&wt=json",
        Endpoint.REPLICA: "/solr/admin/collections?action=clusterstatus&wt=json",
        Endpoint.DOCUMENT_COUNT: "/solr/admin/cores?wt=json"
    }

    class returnValue:
        def __init__(self, name, value, tags):
            self.name = name
            self.value = value
            self.tags = tags

        def get_value(self):
            return self.value

        def get_tags(self):
            return self.tags

        def get_name(self):
            return self.name

    def __init__(self, version, instance):
        self.version = version
        self.instance = instance
        self.ports = instance["ports"]
        self.host = instance["host"]

    def check(self):
        ret = [
            self._get_live_nodes(),
            self._get_shards(),
            self._get_replica(),
            self._get_document_count()
        ]
        return ret

    def get_major_number_version(self):
        return int(self.version[0:1])

    @staticmethod
    def format_url(host, port, handler):
        ret = "http://" + host + ":" + str(port) + handler
        return ret

    @staticmethod
    def get_url(host, ports, handler):
        found = False
        for port in ports:
            try:
                if found is True:
                    break
                url = SolrMetrics.format_url(host, port, handler)
                data = urllib2.urlopen(url)
                obj = json.load(data)
                found = True
            except:
                found = False
        if found is True:
            return obj
        else:
            return {}

    def _get_url(self, handler):
        return SolrMetrics.get_url(self.host, self.ports, handler)

    def _get_live_nodes(self):
        ret = []
        obj = self._get_url(SolrMetrics.URL[SolrMetrics.Endpoint.LIVE_NODES])

        if len(obj) > 0:
            try:
                ret.append(self.returnValue(self.METRIC_NAME_ENUM.LIVE_NODES, len(obj["cluster"]["live_nodes"]), None))
            except KeyError:
                pass
        return ret

    def _get_shards(self):
        ret = []
        obj = self._get_url(SolrMetrics.URL[SolrMetrics.Endpoint.SHARDS])
        if len(obj) > 0:
            for collection in obj["cluster"]["collections"]:
                num_shards = len(obj["cluster"]["collections"][collection]["shards"])
                assert isinstance(collection, object)
                tag = [self.TAG_NAME[self.Tag.COLLECTION] % collection]
                ret.append(self.returnValue(self.METRIC_NAME_ENUM.SHARDS, num_shards, tag))
        return ret


    def _get_replica(self):
        class replica_per_node:
            pass

        ret = []
        obj = self._get_url(SolrMetrics.URL[SolrMetrics.Endpoint.REPLICA])
        if len(obj) > 0:
            for collection in obj["cluster"]["collections"]:
                for shard in obj["cluster"]["collections"][collection]["shards"]:
                    replica_per_node_map = {}
                    for replica in obj["cluster"]["collections"][collection]["shards"][shard]["replicas"]:
                        if obj["cluster"]["collections"][collection]["shards"][shard]["replicas"][replica]["state"] == "active":
                            node_name = obj["cluster"]["collections"][collection]["shards"][shard]["replicas"][replica]["node_name"]
                            if replica_per_node_map.has_key(node_name):
                                replica_per_node_map[node_name].len = replica_per_node_map[node_name].len + 1
                            else:
                                new_entry = replica_per_node()
                                new_entry.len = 1
                                new_entry.name = node_name
                                new_entry.collection = collection
                                new_entry.shard = shard
                                replica_per_node_map[node_name] = new_entry
                    for node_name in replica_per_node_map:
                        tags = [
                            self.TAG_NAME[self.Tag.NODE] % node_name,
                            self.TAG_NAME[self.Tag.COLLECTION] % replica_per_node_map[node_name].collection,
                            self.TAG_NAME[self.Tag.SHARD] % replica_per_node_map[node_name].shard
                        ]
                        ret.append(self.returnValue(self.METRIC_NAME_ENUM.REPLICA, replica_per_node_map[node_name].len, tags))
        return ret

    def _get_document_count(self):
        ret = []
        obj = self._get_url(SolrMetrics.URL[SolrMetrics.Endpoint.DOCUMENT_COUNT])
        if len(obj) > 0:
            for replica_alias in obj["status"]:
                collection = obj["status"][replica_alias]["cloud"]["collection"]
                shard = obj["status"][replica_alias]["cloud"]["shard"]
                replica = obj["status"][replica_alias]["cloud"]["replica"]
                num_docs = obj["status"][replica_alias]["index"]["numDocs"]
                tags = [
                    self.TAG_NAME[self.Tag.COLLECTION] % collection,
                    self.TAG_NAME[self.Tag.SHARD] % shard,
                    self.TAG_NAME[self.Tag.REPLICA] % replica
                ]
                ret.append(self.returnValue(self.METRIC_NAME_ENUM.DOCUMENT_COUNT, num_docs, tags))
        return ret
