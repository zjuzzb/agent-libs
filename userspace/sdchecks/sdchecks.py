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

CHECKS_DIRECTORY = "checks.d"

class YamlConfig:
    def __init__(self):
        #self._root = yaml.load("/opt/draios/etc/dragent.yaml")
        default_file = open("/opt/draios/etc/dragent.default.yaml", "r")
        self._default_root = yaml.load(default_file.read())
        default_file.close()

    def get_merged_sequence(self, key):
        return self._default_root[key]

class Config:
    def __init__(self):
        self._yaml_config = YamlConfig()
        self.checks = {}
        for check in self._yaml_config.get_merged_sequence("datadog_checks"):
            try:
                check_module = imp.load_source('checksd_%s' % check["name"], os.path.join(CHECKS_DIRECTORY, check["name"] + ".py"))
            except Exception, e:
                traceback_message = traceback.format_exc()
                # There is a configuration file for that check but the module can't be imported
                #init_failed_checks[check_name] = {'error':e, 'traceback':traceback_message}
                #log.exception('Unable to import check module %s.py from checks.d' % check_name)
                print 'Unable to import check module %s.py from checks.d: %s' % (check["name"], traceback_message)
                continue

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
                print 'Unable to find AgentCheck class for %s' % check["name"]
            else:
                check["class"] = check_class
            self.checks[check["name"]] = check

def main():
    config = Config()
    agentConfig = {
        "is_developer_mode": False
    }
    print repr(config.checks)
    known_instances = {}
    mymnt = nspy.open("/proc/self/ns/mnt")
    mynet = nspy.open("/proc/self/ns/net")
    #while True:
    #command_s = raw_input();
    queue = posix_ipc.MessageQueue("/sdchecks", os.O_CREAT)
    while True:
        #command_s = '[{"pid": 23801, "vpid": 1, "check": "redisdb"}, {"pid": 789, "vpid": 1, "check": "mongo"}]'
        command_s, priority = queue.receive()
        print "Received command: %s" % command_s
        processes = json.loads(command_s)["body"]
        for p in processes:
            try:
                instance_d = known_instances[p["pid"]]
            except KeyError:
                check_conf = config.checks[p["check"]]
                instances = [check_conf["conf"], ]
                check_instance = check_conf["class"]("testname", None, agentConfig, instances)
                instance_d = { "instance": check_instance }
                if p["vpid"] != p["pid"]:
                    instance_d["netns"] = nspy.open("/proc/%d/ns/net" % p["pid"])
                    instance_d["mntns"] = nspy.open("/proc/%d/ns/mnt" % p["pid"])
                known_instances[p["pid"]] = instance_d

            if instance_d.has_key("netns"):
                nspy.setns(instance_d["netns"])
                nspy.setns(instance_d["mntns"])
            instance_d["instance"].run()
            nspy.setns(mynet)
            nspy.setns(mymnt)
            print json.dumps({ "metrics": instance_d["instance"].get_metrics(),
                               "service_checks": instance_d["instance"].get_service_checks()})
        print "\n"

if __name__ == "__main__":
    main()