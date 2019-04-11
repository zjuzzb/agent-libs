#!/usr/bin/env python
import argparse
import atexit
import hashlib
import os
import os.path
import subprocess
import sys
from collections import defaultdict
from datetime import datetime
from jq import jq

import simplejson as json
from IPython import embed
from google.protobuf.text_format import Merge as parse_text_protobuf
from google.protobuf.pyext._message import RepeatedCompositeContainer, ScalarMapContainer
from google.protobuf.descriptor import FieldDescriptor
from protobuf_to_dict import protobuf_to_dict
from hashlib import md5

import draios_pb2


def print_ts_header(ts):
    print >> sys.stderr, "###### sample ts=%s ######" % ts.strftime("%Y-%m-%d %H:%M:%S")


# this class parses text dumped protobuf from the agent
# they can be enabled with "metricsfile: { location: metrics }"
# on dragent.yaml
# it works if the agent is still running and will report data
# continously using `tail -f`
class MetricsFile(object):
    def __init__(self, path, tail=False):
        if tail:
            self._tail = subprocess.Popen(["tail", "-f", path], stdout=subprocess.PIPE)
            atexit.register(self.close_tail)
            self._file = self._tail.stdout
        else:
            self._file = open(path)

        # Detect if it's a "metrics {" or "timestamp_ns" file
        self._last_line = self._file.readline()
        while True:
            if self._last_line.startswith("timestamp_ns"):
                self.proto_start = "timestamp_ns"
                break
            elif self._last_line.startswith("metrics {"):
                self.proto_start = "metrics {"
                break
            else:
                self._last_line = self._file.readline()

    def next(self):
        ascii_repr = self._last_line
        self._last_line = self._file.readline()
        if len(self._last_line) == 0:
            raise StopIteration()
        while not self._last_line.startswith(self.proto_start):
            ascii_repr += self._last_line
            self._last_line = self._file.readline()
            if len(self._last_line) == 0:
                break
        # Trim "metrics {"
        if self.proto_start == "metrics {":
            ascii_repr = "\n".join(ascii_repr.split("\n")[1:-2])
        metrics = draios_pb2.metrics()
        parse_text_protobuf(ascii_repr, metrics)
        return metrics

    def __iter__(self):
        return self

    def close_tail(self):
        self._tail.kill()


def walk_protos(args, path, filter_f, ext="dam"):
    for root, dirs, files in os.walk(path, topdown=False):
        if args.reorder:
            # dumb way to reorder timestamps, assuming the file format is
            # <timestamp>.dam
            files.sort()
        for name in files:
            if name.endswith(ext):
                fullpath = os.path.join(root, name)
                analyze_proto(args, fullpath, filter_f)


class KubernetesCheck(object):
    def __init__(self, args):
        self.kubernetes_delegated_nodes = set()
        self.running_containers = set()
        self.kubernetes_containers = set()
        self.containers_by_id = {}
        self.deployments = set()
        self.k8s_nodes = set()
        self.nodes = set()
        self.k8s_pods = set()

    def __call__(self, m, _mobj, path):
        if "kubernetes" in m:
            self.kubernetes_delegated_nodes.add((m["machine_id"], m["hostinfo"]["hostname"]))
            for pod in m["kubernetes"]["pods"]:
                for c in pod["container_ids"]:
                    container_id = c[9:12 + 9]
                    self.kubernetes_containers.add(container_id)
                self.k8s_pods.add(pod["common"]["uid"])
            for deployment in m["kubernetes"]["deployments"]:
                self.deployments.add(deployment["common"]["name"])
            for node in m["kubernetes"]["nodes"]:
                self.k8s_nodes.add((node["common"]["uid"], node["common"]["name"]))
        if "containers" in m:
            for c in m["containers"]:
                self.running_containers.add(c["id"])
                self.containers_by_id[c['id']] = (c["name"])
        self.nodes.add((m["machine_id"], m["hostinfo"]["hostname"]))

    def summary(self):
        print "Delegated: %s" % str(self.kubernetes_delegated_nodes)
        print "matching containers=%d" % len(self.running_containers.intersection(self.kubernetes_containers))
        # for cid in running_containers.intersection(self.kubernetes_containers):
        #  print "name=%s" % self.containers_by_id[cid]
        print "running_containers=%d" % len(self.running_containers)
        print "k8s_containers=%d" % len(self.kubernetes_containers)
        print "k8s_pods=%d" % len(self.k8s_pods)
        print "only on k8s containers=%d" % len(self.kubernetes_containers.difference(self.running_containers))
        print "only running containers=%d" % len(self.running_containers.difference(self.kubernetes_containers))
        # for cid in self.running_containers.difference(self.kubernetes_containers):
        #  print "name=%s" % self.containers_by_id[cid]
        print "deployments=%s" % str(self.deployments)
        print "k8s_nodes=%d\n%s" % (len(self.k8s_nodes), str(self.k8s_nodes))
        print "nodes=%d\n%s" % (len(self.k8s_nodes), str(self.nodes))


class MesosCheck(object):
    def __init__(self, args):
        self.masterSamplesWithMesos = 0
        self.mesosMasters = set()
        self.containers = set()
        self.mesosTasks = set()
        self.masterSamples = 0
        self.runningMesosTasks = set()
        self.marathon_task_ids = set()
        self.frameworks = {}
        self.host_by_task = {}

    def __call__(self, m, _mobj, path):
        if "mesos" in m:
            mesos = m["mesos"]
            for framework in mesos["frameworks"]:
                name = framework["common"]["name"]
                if name not in self.frameworks:
                    self.frameworks[name] = set()
                if "tasks" in framework:
                    for task in framework["tasks"]:
                        self.mesosTasks.add(task["common"]["uid"])
                        self.frameworks[name].add(task["common"]["uid"])
            if "groups" in mesos:
                for group in mesos['groups']:
                    self.parse_marathon_group(group)
            self.mesosMasters.add(m["machine_id"])
            self.masterSamplesWithMesos += 1
        if "containers" in m:
            for c in m["containers"]:
                self.containers.add(c["id"])
                if "mesos_task_id" in c:
                    self.runningMesosTasks.add(c["mesos_task_id"])
                    self.host_by_task[c["mesos_task_id"]] = m["hostinfo"]["hostname"]

        if m["machine_id"] in self.mesosMasters:
            self.masterSamples += 1

    def parse_marathon_group(self, group):
        if "groups" in group:
            for subgroup in group["groups"]:
                self.parse_marathon_group(subgroup)
        if "apps" in group:
            for app in group["apps"]:
                if "task_ids" in app:
                    for t in app["task_ids"]:
                        self.marathon_task_ids.add(t)

    def summary(self):
        print "masters=%s" % str(self.mesosMasters)
        print "masterSamples=%d masterSamplesWithMesos=%d" % (self.masterSamples, self.masterSamplesWithMesos)
        print "containers=%d" % len(self.containers)
        print "mesos_tasks=%d" % len(self.mesosTasks)
        print "running_mesos_tasks=%d" % len(self.runningMesosTasks)
        matching_mesos_tasks = self.runningMesosTasks.intersection(self.mesosTasks)
        print "matching_mesos_tasks=%d" % len(matching_mesos_tasks)
        matching_marathon_tasks = self.runningMesosTasks.intersection(self.marathon_task_ids)
        print "matching_marathon_tasks=%d" % len(matching_marathon_tasks)
        print "Unmatching mesos_tasks=%s" % str(self.runningMesosTasks.difference(matching_mesos_tasks))
        print "Unmatching marathon_tasks=%s" % str(self.runningMesosTasks.difference(matching_marathon_tasks))
        frameworks = {k: len(v) for k, v in self.frameworks.items()}
        print "tasks per framework %s" % str(frameworks)
        host_no_marathon_matches = set()
        for t in self.marathon_task_ids.difference(matching_marathon_tasks):
            if t in self.host_by_task:
                host_no_marathon_matches.add(self.host_by_task[t])
        print "hosts with no matches = %s" % host_no_marathon_matches
        embed()


class FollowContainer(object):
    def __init__(self, args):
        self.container_to_follow = args
        self.print_header = True

    def __call__(self, m, _mobj, path):
        for c in m["containers"]:
            if c["id"] == self.container_to_follow:
                print "Present"
        for p in m["programs"]:
            details = p["procinfo"]["details"]
            if "container_id" in details:
                if details["container_id"] == self.container_to_follow:
                    print "Present on processes"
                    break


class ContainerProcessChecker(object):

    def __init__(self, args):
        self.containers = {}
        self.container_processes = {}
        self.processes_no_containers = set()
        self.print_header = True

    def __call__(self, m, _mobj, path):
        containers = {}
        container_processes = {}
        processes_no_containers = set()
        if "containers" not in m:
            return
        for c in m["containers"]:
            containers[c["id"]] = c["name"]
        for p in m["programs"]:
            details = p["procinfo"]["details"]
            if "container_id" in details:
                container_processes[details["container_id"]] = details["comm"]
            else:
                processes_no_containers.add(hashlib.md5(str(details) + str(p["pids"])).hexdigest())

        # Print current sample
        print "%d total processes" % len(m["programs"])
        self._print_status(containers, container_processes, processes_no_containers)

        # Aggregate data
        self.containers.update(containers)
        self.container_processes.update(container_processes)
        self.processes_no_containers = self.processes_no_containers.union(processes_no_containers)

    def _print_status(self, containers, container_processes, processes_no_containers):
        container_set = set(containers.keys())
        processes_set = set(container_processes.keys())
        print "\n%d Containers without processes:" % len(container_set.difference(processes_set))
        for c in container_set.difference(processes_set):
            print "%s:%s" % (c, containers[c])
        print "\n%d Processes without containers:" % len(processes_set.difference(container_set))
        for c in processes_set.difference(container_set):
            print "%s:%s" % (c, container_processes[c])
        print "\nProcesses out of containers: %d" % len(processes_no_containers)

    def summary(self):
        self._print_status(self.containers, self.container_processes, self.processes_no_containers)


class FlameGraph(object):
    print_header = False

    def __init__(self, args):
        self.sizes = defaultdict(int)

    def get_pb_sizes(self, pb, path):
        total_len = len(pb.SerializePartialToString())
        children = 0
        for f in pb.DESCRIPTOR.fields:
            name = f.name
            subpath = '{};{}'.format(path, name)
            if f.message_type is None:
                continue
            val = getattr(pb, name)
            if isinstance(val, RepeatedCompositeContainer):
                for item in val:
                    delta = self.get_pb_sizes(item, subpath)
                    if delta > 0:
                        children += delta
            elif isinstance(val, ScalarMapContainer):
                continue
            else:
                delta = self.get_pb_sizes(val, subpath)
                if delta > 0:
                    children += delta
        self.sizes[path] += total_len - children
        return total_len

    def __call__(self, _m, mobj, path):
        self.get_pb_sizes(mobj, 'metrics')

    def summary(self):
        for k, v in sorted(self.sizes.items()):
            if v > 0:
                print '{} {}'.format(k, v)

class DeepAnalysis(object):
    print_header = False

    def __init__(self, args):
        # maps a path to a size
        self.subtree_size = defaultdict(int)
        # maps a path to a data hash
        # don't need it directly here, but necessary for
        # cross-time comparisons
        self.subtree_data = {}
        self.subtree_data_hr = {}
        # maps a data hash to the path where it occurs.
        self.hash_locations = {}
        self.count = 0

        # Note: there is SOME risk here that we are over aggressive. Consider if
        # we have a uint32 with value 0, and a uint64 with value 0. These will be the "same"
        # as far as the maps are concerned, but are in reality different. We don't foresee
        # this being a particularly big problem

    def scalar_stuff(self, value, f, path):
        # grab the size based on the type...but set integer types to 0...since not worth it
        if f.type is FieldDescriptor.TYPE_DOUBLE or FieldDescriptor.TYPE_INT64 or FieldDescriptor.TYPE_UINT64 or FieldDescriptor.TYPE_FIXED64 or FieldDescriptor.TYPE_SFIXED64 or FieldDescriptor.TYPE_SINT64:
            self.subtree_size[path] = 0
        elif f.type is FieldDescriptor.TYPE_FLOAT or FieldDescriptor.TYPE_INT32 or FieldDescriptor.TYPE_FIXED32 or FieldDescriptor.TYPE_UINT32 or FieldDescriptor.TYPE_ENUM or FieldDescriptor.TYPE_SFIXED32 or FieldDescriptor.TYPE_SINT32:
            self.subtree_size[path] = 0
        elif f.type is FieldDescriptor.TYPE_BOOL:
            self.subtree_size[path] = 0
        elif f.type is FieldDescriptor.TYPE_STRING:
            self.subtree_size[path] = len(value)
        else:
            assert False, "Unhandled scalar type"

        self.subtree_data[path] = value
        if value not in self.hash_locations:
            self.hash_locations[value] = []
        self.hash_locations[value].append(path)

    def deep_analyze(self, pb, path):
        data = pb.SerializePartialToString()
        self.subtree_size[path] = len(data)
        self.subtree_data[path] = data
        self.subtree_data_hr[path] = pb
        if data not in self.hash_locations:
            self.hash_locations[data] = []
        self.hash_locations[data].append(path)

        for f in pb.DESCRIPTOR.fields:
            if f.label is FieldDescriptor.LABEL_REPEATED: # repeated field
                vals = getattr(pb, f.name)
                for i in range(0, len(vals)):
                    item = vals[i]
                    subpath = '{};{}.{}'.format(path, f.name, i)
                    if f.message_type is None: # first deal with scalarrrs
                        self.scalar_stuff(item, f, subpath)
                    else: # repeated message
                        self.deep_analyze(item, subpath)
            else:
                subpath = '{};{}'.format(path, f.name)
                if f.message_type is None: #stand-alone scalar
                    self.scalar_stuff(getattr(pb, f.name), f, subpath)
                else: # regular sub message
                    self.deep_analyze(getattr(pb, f.name), subpath)

    def __call__(self, _m, mobj, path):
        self.count += 1
        self.deep_analyze(mobj, path + '::metrics')

    def summary(self):
        total_savings = defaultdict(int)
        found_data = set()
        found_data.add(0) # seriously...we don't need to dedupe 0's
        for k in self.subtree_data:
            if len(self.hash_locations[self.subtree_data[k]]) > 1 and self.subtree_size[k] > 0 and self.subtree_data[k] not in found_data: #only take multiples
                total_savings[k] = self.subtree_size[k] * (len(self.hash_locations[self.subtree_data[k]]) - 1)
                found_data.add(self.subtree_data[k])

        # using magic, sorts hashes by most savings
        most_savings = sorted(total_savings.iteritems(), key=lambda x: x[1], reverse=True)

        # print out paths of top 20
        for k,v in most_savings:
            print "Potential Savings: ", v/self.count, " bytes per message
            print "Data:"
            print ""
            print self.subtree_data_hr[k]
            print "Paths:"
            for i in self.hash_locations[self.subtree_data[k]]:
                print "\t",i
            print "\n\n"

class BinaryOutput(object):
    print_header = True

    def __init__(self, args):
        pass

    def __call__(self, m, mobj, path):
        machine_id = m['machine_id'].replace(':', '-')
        timestamp_ns = m['timestamp_ns']

        basedir = '/out/{}'.format(machine_id)
        target = '{}/{}.dam'.format(basedir, timestamp_ns)

        if not os.path.exists(basedir):
            os.makedirs(basedir)

        print 'writing to: {}'.format(target)
        with open(target, 'wb') as dam:
            dam.write('\x02\x01')
            dam.write(mobj.SerializeToString())


class TextOutput(object):
    print_header = True

    def __init__(self, args):
        pass

    def __call__(self, m, mobj, path):
        print str(mobj)


class EnvFuzz(object):
    print_header = True

    def __init__(self, args):
        self.filter_args = {}
        if args:
            for arg in args.split():
                k, v = arg.split('=')
                if k == 'count':
                    v = int(v)
                self.filter_args[k] = v
        print self.filter_args

    def rehash(self, hv):
        out_len = len(hv)
        new_hv = md5(hv).hexdigest()
        while len(new_hv) < out_len:
            new_hv += md5(new_hv).hexdigest()
        return new_hv[:out_len]

    def new_machine_id(self, machine_id):
        raw_id = machine_id.replace(':', '').decode('hex')
        raw_id = md5(raw_id).digest()[0:6]
        return ':'.join(xd.encode('hex') for xd in raw_id)

    def fuzz(self, mobj):
        machine_id = self.new_machine_id(mobj.machine_id)
        mobj.machine_id = machine_id

        machine_id = machine_id.replace(':', '-')
        timestamp_ns = mobj.timestamp_ns

        for env in mobj.environments:
            env.hash = self.rehash(env.hash)

        for prog in mobj.programs:
            prog.environment_hash = self.rehash(prog.environment_hash)

        basedir = '/out/{}'.format(machine_id)
        target = '{}/{}.dam'.format(basedir, timestamp_ns)

        if not os.path.exists(basedir):
            os.makedirs(basedir)

        print 'writing to: {}'.format(target)
        with open(target, 'wb') as dam:
            dam.write('\x02\x01')
            dam.write(mobj.SerializeToString())

        return mobj

    def __call__(self, m, mobj, path):
        for i in range(self.filter_args.get('count', 1)):
            mobj = self.fuzz(mobj)


FILTERS = {
    'k8s': KubernetesCheck,
    'mesos': MesosCheck,
    'follow_container': FollowContainer,
    'container_procs': ContainerProcessChecker,
    'binary_output': BinaryOutput,
    'text_output': TextOutput,
    'env_fuzz': EnvFuzz,
    'flame_graph': FlameGraph,
    'deep_analysis' : DeepAnalysis,
}

# backwards-compatible names
OLD_FILTERS = {
    'kubernetes_check': KubernetesCheck,
    'MesosCheck': MesosCheck,
    'FollowContainer': FollowContainer,
    'ContainerProcessChecker': ContainerProcessChecker,
}


def create_filter(args):
    if args.filter:
        try:
            f = FILTERS[args.filter]
        except KeyError:
            try:
                f = OLD_FILTERS[args.filter]
            except KeyError:
                raise RuntimeError("Invalid filter {}, valid names are: {}".format(
                    args.filter, ', '.join(FILTERS.keys() + OLD_FILTERS.keys())))
        return f(args.filter_args)
    elif args.jq_filter:
        jq_filter = jq(args.jq_filter)
        return lambda m, mobj: jq_filter.transform(m, multiple_output=True)
    else:
        return lambda m, mobj: m


def analyze_proto(args, path, filter_f):
    if path.endswith("dam") or args.binary:
        with open(path, "rb") as f:
            f.seek(2)
            metrics = draios_pb2.metrics.FromString(f.read())
            process_metrics(metrics, filter_f, path)
    else:
        if args.reorder:
            ml = [metrics for metrics in MetricsFile(path)]
            ml.sort(key=lambda m: m.timestamp_ns)
            for m in ml:
                process_metrics(m, filter_f, path)
        else:
            for metrics in MetricsFile(path, tail=args.follow):
                process_metrics(metrics, filter_f, path)


def process_metrics(metrics, filter_f, filename):
    ts = datetime.fromtimestamp(metrics.timestamp_ns / 1000000000)
    try:
        metrics_d = protobuf_to_dict(metrics)
    except UnicodeDecodeError:
        print("Error processing sample %s:%s", metrics.timestamp_ns, metrics.machine_id)
        return
    metrics_j = filter_f(metrics_d, metrics, filename)
    if metrics_j:
        print_ts_header(ts)
        print(json.dumps(metrics_j, indent=2))
        print("\n")
    else:
        if getattr(filter_f, "print_header", False):
            print_ts_header(ts)
        else:
            sys.stderr.write('.')
            sys.stderr.flush()


# text files
#
def main():
    parser = argparse.ArgumentParser(description="Analyze protobufs using JQ filters")
    parser.add_argument("--follow", dest="follow", required=False, default=False, action='store_true',
                        help="Follow the file as tail -f does")
    parser.add_argument("--binary", dest="binary", required=False, default=False, action='store_true',
                        help="path is a binary file")
    parser.add_argument("--reorder", dest="reorder", required=False, default=False, action="store_true",
                        help="reorder metrics by timestamp")
    parser.add_argument("--jq-filter", type=str, required=False, help="JQ filter to use")
    parser.add_argument("--filter", type=str, required=False, help="Native functions available", choices=FILTERS.keys())
    parser.add_argument("--filter-args", type=str, required=False, default="", help="Native functions args")
    parser.add_argument("path", type=str, help="File to parse")
    args = parser.parse_args()

    print >> sys.stderr, "Running with args: %s" % repr(args)

    if args.path == "last":
        metric_files = [p for p in os.listdir("/opt/draios/metrics/") if p.endswith(".dams")]
        path = os.path.join("/opt/draios/metrics/", metric_files[-1])
    else:
        path = args.path

    filter_f = create_filter(args)
    if os.path.isdir(path):
        walk_protos(args, path, filter_f)
    else:
        analyze_proto(args, path, filter_f)
    print >> sys.stderr, ""
    if hasattr(filter_f, "summary"):
        filter_f.summary()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Ctrl-C closing..")
