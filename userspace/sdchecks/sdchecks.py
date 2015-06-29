import yaml
import imp
import simplejson as json
import os.path
import traceback
import inspect
from checks import AgentCheck
import posix_ipc
import os
import nspy
import re

CHECKS_DIRECTORY = "checks.d"

class YamlConfig:
    def __init__(self):
        #self._root = yaml.load("/opt/draios/etc/dragent.yaml")
        default_file = open("/opt/draios/etc/dragent.default.yaml", "r")
        self._default_root = yaml.load(default_file.read())
        default_file.close()

    def get_merged_sequence(self, key):
        return self._default_root[key]

class DatadogCheck:
    def __init__(self, node):
        self.name = node["name"]
        self.conf = node["conf"]
        try:
            check_module = imp.load_source('checksd_%s' % self.name, os.path.join(CHECKS_DIRECTORY, self.name + ".py"))
        except Exception, e:
            traceback_message = traceback.format_exc()
            # There is a configuration file for that check but the module can't be imported
            #init_failed_checks[check_name] = {'error':e, 'traceback':traceback_message}
            #log.exception('Unable to import check module %s.py from checks.d' % check_name)
            raise Exception('Unable to import check module %s.py from checks.d: %s' % (self.name, traceback_message))

        # We make sure that there is an AgentCheck class defined
        check_class = None
        classes = inspect.getmembers(check_module, inspect.isclass)
        for _, clsmember in classes:
            if clsmember == AgentCheck:
                continue
            if issubclass(clsmember, AgentCheck):
                check_class = clsmember
                if AgentCheck in clsmember.__bases__:
                    continue
                else:
                    break
        if check_class is None:
            raise Exception('Unable to find AgentCheck class for %s' % self.name)
        else:
            self.check_class = check_class

    def __repr__(self):
        return "DatadogCheck(name=%s, conf=%s, check_class=%s" % (self.name, repr(self.conf), repr(self.check_class))

class DatadogCheckInstance:
    mymnt = nspy.open("/proc/self/ns/mnt")
    mynet = nspy.open("/proc/self/ns/net")
    TOKEN_PATTERN = re.compile("\{.+\}")
    agentConfig = {
        "is_developer_mode": False
    }
    PROC_DATA_FROM_TOKEN = {
        "port": lambda p: p["ports"][0],
        "port.high": lambda p: p["ports"][-1],
    }
    def __init__(self, check, proc_data):
        self.pid = proc_data["pid"]
        self.vpid = proc_data["vpid"]
        self.check_instance = check.check_class("testname", None, self.agentConfig, None)
        if self.vpid != self.pid:
            self.netns = nspy.open("/proc/%d/ns/net" % self.pid)
            self.mntns = nspy.open("/proc/%d/ns/mnt" % self.pid)

        self.instance_conf = {}
        for key, value in check.conf.items():
            if type(value) is str:
                self.instance_conf[key] = self._expand_template(value, proc_data)
            else:
                self.instance_conf[key] = value
        print "Instantiated conf for check %s: %s" % (check.name, repr(self.instance_conf))
    def run(self):
        if self.pid != self.vpid:
                nspy.setns(self.netns)
                nspy.setns(self.mntns)
        self.check_instance.check(self.instance_conf)
        nspy.setns(self.mynet)
        nspy.setns(self.mymnt)
        return self.check_instance.get_metrics(), self.check_instance.get_service_checks()

    def _expand_template(self, value, proc_data):
        ret = ""
        lastpos = 0
        for token in re.finditer(self.TOKEN_PATTERN, value):
            ret += value[lastpos:token.start()]
            lastpos = token.end()
            token_key = value[token.start()+1:token.end()-1]
            ret += str(self.PROC_DATA_FROM_TOKEN[token_key](proc_data))
        ret += value[lastpos:len(value)]
        if ret.isdigit():
            ret = int(ret)
        return ret

class Config:
    def __init__(self):
        self._yaml_config = YamlConfig()
        check_confs = self._yaml_config.get_merged_sequence("datadog_checks")
        self.checks = {c.name: c for c in map(lambda c: DatadogCheck(c), check_confs)}

def main():
    config = Config()
    print repr(config.checks)
    known_instances = {}
    queue = posix_ipc.MessageQueue("/sdchecks", os.O_CREAT)
    while True:
        command_s, priority = queue.receive()
        print "Received command: %s" % command_s
        processes = json.loads(command_s)["body"]
        for p in processes:
            try:
                check_instance = known_instances[p["pid"]]
            except KeyError:
                check_conf = config.checks[p["check"]]
                check_instance = DatadogCheckInstance(check_conf, p)

            metrics, service_checks = check_instance.run()
            print json.dumps({ "metrics": metrics,
                               "service_checks": service_checks})
        print "\n"

if __name__ == "__main__":
    main()