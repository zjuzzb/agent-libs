import draios_pb2
from google.protobuf.text_format import Merge as parse_text_protobuf
import pytest
import subprocess
from glob import glob
import time
import os
import sys

ENV_DATA_DIR="envs_data/"
ENV_DIR="envs/"

class MetricsFile(object):
  def __init__(self, path):
    self._file = open(path)
    self._last_line = self._file.readline()

  def next(self):
    ascii_repr = self._last_line
    self._last_line = self._file.readline()
    if len(self._last_line) == 0:
      raise StopIteration()
    while not self._last_line.startswith("timestamp_ns"):
      ascii_repr += self._last_line
      self._last_line = self._file.readline()
      if len(self._last_line) == 0:
        raise StopIteration()
    metrics = draios_pb2.metrics()
    parse_text_protobuf(ascii_repr, metrics)
    return metrics

  def __iter__(self):
    return self

def lastMetricsFile(name):
  all_metric_file = glob("%s/metrics/*" % os.path.join(ENV_DATA_DIR, name))
  all_metric_file.sort()
  return MetricsFile(all_metric_file[-1])

CASSANDRA_METRICS=set([
  u'cassandra.compactions.bytes',
  u'cassandra.compactions.count',
  u'cassandra.compactions.pending',
  u'cassandra.keycache.hits',
  u'cassandra.keycache.requests',
  u'cassandra.read.count',
  u'cassandra.read.total.latency',
  u'cassandra.read.pending',
  u'cassandra.rowcache.hits',
  u'cassandra.rowcache.requests',
  u'cassandra.write.count',
  u'cassandra.write.total.latency',
  u'cassandra.write.pending',
  u'jvm.class.loaded',
  u'jvm.class.unloaded',
  u'jvm.gc.ConcurrentMarkSweep.count',
  u'jvm.gc.ConcurrentMarkSweep.time',
  u'jvm.gc.ParNew.count',
  u'jvm.gc.ParNew.time',
  u'jvm.heap',
  u'jvm.nonHeap',
  u'jvm.thread.count',
  u'jvm.thread.daemon'])

CASSANDRA_RECENT_LATENCY = set([
  u'cassandra.read.latency',
  u'cassandra.write.latency',
])

CASSANDRA_HINTEDHANDOFF = set([
  u'cassandra.hintedhandoff.active',
  u'cassandra.hintedhandoff.pending',
])

@pytest.mark.parametrize("env", [
  "cassandra-2.1",
  "cassandra-2.2",
  "cassandra-latest",
])
def test_cassandra_beans(env):
  cassandraFound=False
  beansPresent = 0
  samples = 0
  expected_metrics = CASSANDRA_METRICS
  if env == "cassandra-2.1":
    expected_metrics = expected_metrics.union(CASSANDRA_RECENT_LATENCY)
  if env == "cassandra-2.1" or env == "cassandra-2.2":
    expected_metrics = expected_metrics.union(CASSANDRA_HINTEDHANDOFF)
  beans = set()
  for m in lastMetricsFile(env):
    samples += 1
    for program in m.programs:
      java = program.procinfo.protos.java
      if java and java.process_name == "cassandra":
        cassandraFound = True
        cassandraMetrics = set()
        for b in java.beans:
          for a in b.attributes:
            cassandraMetrics.add(a.alias)
        if cassandraMetrics == expected_metrics:
          beansPresent += 1
        beans = beans.union(cassandraMetrics)
  assert cassandraFound
  assert beans == expected_metrics
  assert beansPresent > int(float(samples)*0.7)

@pytest.mark.parametrize("env", [
  "redis-traffic"
])
def test_network_by_server_port(env):
  redis_server_found = 0
  redis_server_found_host = 0

  samples = 0
  for m in lastMetricsFile(env):
    samples += 1
    for entry in m.hostinfo.network_by_serverports:
      assert entry.port > 0
      if entry.port == 6379:
        redis_server_found_host += 1
        assert entry.counters.n_aggregated_connections == 1 
    for c in m.containers:
      if c.image == "redis":
        for entry in c.network_by_serverports:
          assert entry.port > 0
          if entry.port == 6379:
            redis_server_found += 1
            # The client part should be empty as we are on the server container
            assert entry.counters.client.bytes_in == 0
            assert entry.counters.client.bytes_out == 0
            assert entry.counters.client.count_in == 0
            assert entry.counters.client.count_out == 0
            assert entry.counters.n_aggregated_connections == 1
      if c.image == "redistraffic_client":
        for entry in c.network_by_serverports:
          assert entry.port > 0
          if entry.port == 6379:
            redis_server_found += 1
            # The server part should be empty as we are on the client container
            assert entry.counters.server.bytes_in == 0
            assert entry.counters.server.bytes_out == 0
            assert entry.counters.server.count_in == 0
            assert entry.counters.server.count_out == 0
            assert entry.counters.n_aggregated_connections == 1
  assert redis_server_found == 2*samples
  assert redis_server_found_host == samples

@pytest.mark.parametrize("env", [
    "redis-traffic"
])
def test_ipv4_connections(env):
  for m in lastMetricsFile(env):
    for conn in m.ipv4_connections:
      assert conn.spid != 0 or conn.dpid != 0
      assert conn.tuple.sport == 0
      assert conn.tuple.dport > 0