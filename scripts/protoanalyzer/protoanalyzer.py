#!/usr/bin/env python
import sys
import time
import draios_pb2
import zlib
import os
import errno
from protobuf_to_dict import protobuf_to_dict
import simplejson as json
from jq import jq
from google.protobuf.text_format import Merge as parse_text_protobuf
from google.protobuf.text_format import MessageToString as serialize_text_protobuf
import os.path
import subprocess
import argparse
import struct
import socket
import atexit

# this class parses text dumped protobuf from the agent
# they can be enabled with "metricsfile: { location: metrics }"
# on dragent.yaml
# it works if the agent is still running and will report data
# continously using `tail -f`
# TODO: it needs improvements tobe able to parse protobufs coming
#       from protoparser
class MetricsFile(object):
  def __init__(self, path, tail=False):
    if tail:
      self._tail = subprocess.Popen(["tail", "-f", path], stdout=subprocess.PIPE)
      atexit.register(self.close_tail)
      self._file = self._tail.stdout
      self._last_line = self._file.readline()
      while not self._last_line.startswith("metrics {"):
        self._last_line = self._file.readline()
    else:
      self._file = open(path)
      self._last_line = self._file.readline()

  def next(self):
    ascii_repr = self._last_line
    self._last_line = self._file.readline()
    if len(self._last_line) == 0:
      raise StopIteration()
    while not self._last_line.startswith("metrics {"):
      ascii_repr += self._last_line
      self._last_line = self._file.readline()
      if len(self._last_line) == 0:
        raise StopIteration()
    # Trim "metrics {"
    ascii_repr = "\n".join(ascii_repr.split("\n")[1:-2])
    metrics = draios_pb2.metrics()
    parse_text_protobuf(ascii_repr, metrics)
    return metrics

  def __iter__(self):
    return self

  def close_tail(self):
    self._tail.kill()

parser = argparse.ArgumentParser(description="Analyze protobufs using JQ filters")
parser.add_argument("--follow", dest="follow", required=False, default=False, action='store_true', help="Follow the file as tail -f does")
parser.add_argument("--binary", dest="binary", required=False, default=False, action='store_true', help="path is a binary file")
parser.add_argument("path", type=str, help="File to parse")
parser.add_argument("jq_filter", type=str, default=".", help="JQ filter to use")
args = parser.parse_args()
print "Running with args: %s" % repr(args)

if args.path == "last":
  metricFiles = [ p for p in os.listdir("/opt/draios/metrics/") if p.endswith(".dams") ]
  path = os.path.join("/opt/draios/metrics/", metricFiles[-1])
else:
  path = args.path
metrics_filter = jq(args.jq_filter)

# text files
#

def process_metrics(metrics):
  print("###### sample ts=%d ######" % metrics.timestamp_ns)
  metrics_d = protobuf_to_dict(metrics)
  print(metrics_filter.transform(metrics_d, text_output=True))
  print("\n")

def main():
  if args.binary:
    # binary files
    #for root, dirs, files in os.walk(path, topdown=False):
      #for name in files:
        #if name.endswith("dam"):
          #fullpath = os.path.join(root, name)
          #print("Processing %s" % fullpath)
          with open(path, "rb") as f:
            f.seek(2)
            metrics = draios_pb2.metrics.FromString(f.read())
            process_metrics(metrics)
            #with open(fullpath+"s", "w") as f2:
            #  f2.write(serialize_text_protobuf(metrics))
  else:
    for metrics in MetricsFile(path, tail=args.follow):
      process_metrics(metrics)

if __name__ == "__main__":
  try:
    main()
  except KeyboardInterrupt:
    print("Ctrl-C closing..")
