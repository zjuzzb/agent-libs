#!/usr/bin/env python
import argparse
import atexit
import hashlib
import os
import os.path
import subprocess
import sys
from datetime import datetime
from jq import jq

import simplejson as json
from IPython import embed
from google.protobuf.text_format import Merge as parse_text_protobuf
from protobuf_to_dict import protobuf_to_dict
from hashlib import md5

import draios_pb2


def print_ts_header(ts):
    print("###### sample ts=%s ######" % ts.strftime("%Y-%m-%d %H:%M:%S"))


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
                raise StopIteration()
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

    def __call__(self, m, _mobj):
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

    def __call__(self, m, _mobj):
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

    def __call__(self, m, _mobj):
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

    def __call__(self, m, _mobj):
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


class BinaryOutput(object):
    print_header = True

    def __init__(self, args):
        pass

    def __call__(self, m, mobj):
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

    def __call__(self, m, mobj):
        for i in range(self.filter_args.get('count', 1)):
            mobj = self.fuzz(mobj)


FILTERS = {
    'k8s': KubernetesCheck,
    'mesos': MesosCheck,
    'follow_container': FollowContainer,
    'container_procs': ContainerProcessChecker,
    'binary_output': BinaryOutput,
    'env_fuzz': EnvFuzz,
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
            process_metrics(metrics, filter_f)
    else:
        if args.reorder:
            ml = [metrics for metrics in MetricsFile(path)]
            ml.sort(key=lambda m: m.timestamp_ns)
            for m in ml:
                process_metrics(m, filter_f)
        else:
            for metrics in MetricsFile(path, tail=args.follow):
                process_metrics(metrics, filter_f)


def process_metrics(metrics, filter_f):
    ts = datetime.fromtimestamp(metrics.timestamp_ns / 1000000000)
    try:
        metrics_d = protobuf_to_dict(metrics)
    except UnicodeDecodeError:
        print("Error processing sample %s:%s", metrics.timestamp_ns, metrics.machine_id)
        return
    metrics_j = filter_f(metrics_d, metrics)
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

    print "Running with args: %s" % repr(args)

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
    print("")
    if hasattr(filter_f, "summary"):
        filter_f.summary()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Ctrl-C closing..")
