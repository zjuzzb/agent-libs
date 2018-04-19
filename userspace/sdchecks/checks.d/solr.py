import json
import urllib2
from sets import Set

from checks import AgentCheck


class Solr(AgentCheck):
    """
    Solr agent check
    """

    # Source
    SOURCE_TYPE_NAME = "solr"

    LIVE_NODES = "live_nodes"
    LIVE_NODES_ENDPOINT = "/solr/admin/collections?action=clusterstatus&wt=json"
    SHARDS = "shards"
    SHARDS_ENDPOINT = LIVE_NODES_ENDPOINT
    REPLICA = "replica"
    REPLICA_ENDPOINT = LIVE_NODES_ENDPOINT
    DOCUMENT_COUNT = "document_count"
    DOCUMENT_COUNT_ENDPOINT = "/solr/admin/cores?wt=json"
    COLLECTION = "collection"
    NODE = "node"

    ENDPOINTS = {LIVE_NODES: LIVE_NODES_ENDPOINT,
                 SHARDS: SHARDS_ENDPOINT,
                 REPLICA: REPLICA_ENDPOINT,
                 DOCUMENT_COUNT: DOCUMENT_COUNT_ENDPOINT}

    METRIC_NAME = {
        LIVE_NODES : "solr.live_nodes",
        SHARDS : "solr.shards",
        REPLICA : "solr.replica",
        DOCUMENT_COUNT: "solr.document_count"
    }

    COLLECTION_TAG_NAME = "solr.collection:%s"
    SHARD_TAG_NAME = "solr.shard:%s"
    NODE_TAG_NAME = "solr.node:%s"
    REPLICA_TAG_NAME = "solr.replica:%s"

    def __init__(self, name, init_config, agentConfig, instances=None):
        AgentCheck.__init__(self, name, init_config, agentConfig, instances)

    def check(self, instance):
        resp = self._get_live_nodes(instance)
        self._get_shards(instance, resp)
        self._get_replica(instance, resp)
        self._get_document_count(instance)

    @staticmethod
    def format_url(host, port, handler):
        ret = "http://" + host + ":" + str(port) + handler
        return ret

    def _get_url(self, host, ports, handler):
        found = False
        for port in ports:
            try:
                if found is True:
                    break
                url = self.format_url(host, port, handler)
                data = urllib2.urlopen(url)
                obj = json.load(data)
                found = True
            except:
                found = False
        if found is True:
            return obj
        else:
            return {}

    def _get_live_nodes(self, instance):
        obj = self._get_url(instance["host"], instance["ports"], self.ENDPOINTS[self.LIVE_NODES])

        if len(obj) > 0:
            try:
                self.gauge(self.METRIC_NAME[self.LIVE_NODES], len(obj["cluster"]["live_nodes"]))
            except KeyError:
                pass
        return obj

    def _get_shards(self, instance, json):
        if json is None or len(json) is 0:
            json = self._get_url(instance["host"], instance["ports"], self.ENDPOINTS[self.SHARDS])
        obj = json
        if len(obj) > 0:
            for collection in obj["cluster"]["collections"]:
                num_shards = len(obj["cluster"]["collections"][collection]["shards"])
                assert isinstance(collection, object)
                tag = [self.COLLECTION_TAG_NAME % collection]
                self.gauge(self.METRIC_NAME[self.SHARDS], num_shards, tag)
        return obj

    def _get_replica(self, instance, json):
        class replica_per_node:
            pass

        if json is None or len(json) is 0:
            json = self._get_url(instance["host"], instance["ports"], self.ENDPOINTS[self.SHARDS])
        obj = json
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
                            self.NODE_TAG_NAME % node_name,
                            self.COLLECTION_TAG_NAME % replica_per_node_map[node_name].collection,
                            self.SHARD_TAG_NAME  % replica_per_node_map[node_name].shard
                        ]
                        self.gauge(self.METRIC_NAME[self.REPLICA], replica_per_node_map[node_name].len, tags)
        return obj

    def _get_document_count(self, instance):
        obj = self._get_url(instance["host"], instance["ports"], self.ENDPOINTS[self.DOCUMENT_COUNT])
        if len(obj) > 0:
            for replica_alias in obj["status"]:
                collection = obj["status"][replica_alias]["cloud"]["collection"]
                shard = obj["status"][replica_alias]["cloud"]["shard"]
                replica = obj["status"][replica_alias]["cloud"]["replica"]
                num_docs = obj["status"][replica_alias]["index"]["numDocs"]
                tags = [
                    self.COLLECTION_TAG_NAME % collection,
                    self.SHARD_TAG_NAME % shard,
                    self.REPLICA_TAG_NAME % replica
                ]
                self.gauge(self.METRIC_NAME[self.DOCUMENT_COUNT], num_docs, tags)