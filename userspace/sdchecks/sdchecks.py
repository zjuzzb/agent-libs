# std
import os.path
import traceback
import inspect
import imp
import os
import re
import resource
import ctypes

# project
from checks import AgentCheck

# 3rd party
import yaml
import simplejson as json
import posix_ipc

RLIMIT_MSGQUEUE = 12
CHECKS_DIRECTORY = "/opt/draios/lib/python/checks.d"

_LIBC = ctypes.CDLL('libc.so.6', use_errno=True)
__NR_setns = 308

try:
    SYSDIG_HOST_ROOT = os.environ["SYSDIG_HOST_ROOT"]
except KeyError:
    SYSDIG_HOST_ROOT = ""

def setns(fd):
    # TODO: test if it works on Centos64
    # TODO: raise an exception if setns fails?
    if hasattr(_LIBC, "setns"):
        return _LIBC.setns(fd, 0)
    else:
        return _LIBC.syscall(__NR_setns, fd, 0)

class YamlConfig:
    def __init__(self):
        with open("/opt/draios/etc/dragent.default.yaml", "r") as default_file:
            self._default_root = yaml.load(default_file.read())
        with open("/opt/draios/etc/dragent.yaml", "r") as custom_file:
            self._root = yaml.load(custom_file.read())
    def get_merged_sequence(self, key):
        return self._default_root[key]

class AppCheck:
    def __init__(self, node):
        self.name = node["name"]
        self.conf = node["conf"]

        try:
            self.display_name = node["display_name"]
        except KeyError:
            self.display_name = None

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
        return "AppCheck(name=%s, conf=%s, check_class=%s" % (self.name, repr(self.conf), repr(self.check_class))

class CannotExpandTemplate(Exception):
    pass

class AppCheckInstance:
    mymnt = os.open("%s/proc/self/ns/mnt" % SYSDIG_HOST_ROOT, os.O_RDONLY)
    mynet = os.open("%s/proc/self/ns/net" % SYSDIG_HOST_ROOT, os.O_RDONLY)
    TOKEN_PATTERN = re.compile("\{.+\}")
    agentConfig = {
        "is_developer_mode": False
    }
    PROC_DATA_FROM_TOKEN = {
        "port": lambda p: p["ports"][0],
        "port.high": lambda p: p["ports"][-1],
    }
    def __init__(self, check, proc_data):
        if check.display_name:
            self.display_name = check.display_name
        else:
            self.display_name = check.name
        self.pid = proc_data["pid"]
        self.vpid = proc_data["vpid"]
        self.check_instance = check.check_class("testname", None, self.agentConfig, None)
        # TODO: improve this check using the inode?
        if self.vpid != self.pid:
            self.netns = os.open("%s/proc/%d/ns/net" % (SYSDIG_HOST_ROOT, self.pid), os.O_RDONLY)
            self.mntns = os.open("%s/proc/%d/ns/mnt" % (SYSDIG_HOST_ROOT, self.pid), os.O_RDONLY)

        self.instance_conf = {}
        for key, value in check.conf.items():
            if type(value) is str:
                self.instance_conf[key] = self._expand_template(value, proc_data)
            else:
                self.instance_conf[key] = value

    def __del__(self):
        if hasattr(self, "netns") and self.netns > 0:
            os.close(self.netns)
        if hasattr(self, "mntns") and self.mntns > 0:
            os.close(self.mntns)

    def run(self):
        if self.pid != self.vpid:
            setns(self.netns)
            setns(self.mntns)
        self.check_instance.check(self.instance_conf)
        setns(self.mynet)
        setns(self.mymnt)
        return self.check_instance.get_metrics(), self.check_instance.get_service_checks()

    def _expand_template(self, value, proc_data):
        try:
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
        except Exception, ex:
            raise CannotExpandTemplate(ex)

class Config:
    def __init__(self):
        self._yaml_config = YamlConfig()
        check_confs = self._yaml_config.get_merged_sequence("app_checks")
        self.checks = {c.name: c for c in map(lambda c: AppCheck(c), check_confs)}

class PosixQueueType:
    SEND = 0
    RECEIVE = 1

class PosixQueue:
    MSGSIZE = 1 << 20
    def __init__(self, name, direction, maxmsgs=3):
        resource.setrlimit(RLIMIT_MSGQUEUE, (10*self.MSGSIZE, 10*self.MSGSIZE))
        self.direction = direction
        self.queue = posix_ipc.MessageQueue(name, os.O_CREAT, mode = 0600,
                                            max_messages = maxmsgs, max_message_size = self.MSGSIZE,
                                            read = (self.direction == PosixQueueType.RECEIVE),
                                            write = (self.direction == PosixQueueType.SEND))

    def close(self):
        self.queue.close()
        self.queue = None

    def send(self, msg):
        try:
            self.queue.send(msg, timeout=0)
            return True
        except posix_ipc.BusyError:
            return False

    def receive(self, timeout=1):
        message, _ = self.queue.receive(timeout)
        return message

    def __del__(self):
        if hasattr(self, "queue"):
            self.close()

def main():
    config = Config()
    print repr(config.checks)
    known_instances = {}
    inqueue = PosixQueue("/sdchecks", PosixQueueType.RECEIVE)
    outqueue = PosixQueue("/dragent_app_checks", PosixQueueType.SEND)

    try:
        while True:
            command_s = inqueue.receive(None)
            response_body = []
            #print "Received command: %s" % command_s
            command = json.loads(command_s)
            processes = command["body"]
            for p in processes:
                try:
                    check_instance = known_instances[p["pid"]]
                except KeyError:
                    check_conf = config.checks[p["check"]]
                    check_instance = AppCheckInstance(check_conf, p)
                    known_instances[p["pid"]] = check_instance
                metrics, service_checks = check_instance.run()
                response_body.append({ "pid": int(check_instance.pid),
                                        "display_name": check_instance.display_name,
                                                 "metrics": metrics,
                                   "service_checks": service_checks})
            response = {
                "id": command["id"],
                "body": response_body
            }
            response_s = json.dumps(response)
            #print "Response: %s\n" % response_s
            outqueue.send(response_s)
    except KeyboardInterrupt:
        pass
