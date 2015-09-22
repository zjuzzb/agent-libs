# -*- coding: utf-8 -*-
# std
import os.path
import traceback
import inspect
import imp
import os
import re
import resource
import ctypes
import logging
from datetime import datetime, timedelta

# project
from checks import AgentCheck
from util import get_hostname

# 3rd party
import yaml
import simplejson as json
import posix_ipc

RLIMIT_MSGQUEUE = 12
CHECKS_DIRECTORY = "/opt/draios/lib/python/checks.d"

try:
    SYSDIG_HOST_ROOT = os.environ["SYSDIG_HOST_ROOT"]
except KeyError:
    SYSDIG_HOST_ROOT = ""

_LIBC = ctypes.CDLL('libc.so.6', use_errno=True)
__NR_setns = 308

def setns(fd):
    if hasattr(_LIBC, "setns"):
        return _LIBC.setns(fd, 0)
    else:
        # Call syscall directly if glib does not have setns (eg. CentOS)
        return _LIBC.syscall(__NR_setns, fd, 0)

def build_ns_path(pid, ns):
    return "%s/proc/%d/ns/%s" % (SYSDIG_HOST_ROOT, pid, ns)

class YamlConfig:
    def __init__(self):
        try:
            with open("/opt/draios/etc/dragent.default.yaml", "r") as default_file:
                self._default_root = yaml.load(default_file.read())
        except Exception as ex:
            self._default_root = {}
            logging.error("Cannot read config file dragent.default.yaml: %s" % ex.message)
        try:
            with open("/opt/draios/etc/dragent.yaml", "r") as custom_file:
                self._root = yaml.load(custom_file.read())
        except Exception as ex:
            self._root = {}
            logging.error("Cannot read config file dragent.yaml: %s" % ex.message)

    def get_merged_sequence(self, key, default=[]):
        ret = default
        if self._root.has_key(key):
            ret += self._root[key]
        if self._default_root.has_key(key):
            ret += self._default_root[key]
        return ret

    def get_single(self, key, subkey, default_value=None):
        # TODO: now works only for key.subkey, more general implementation may be needed
        if self._root.has_key(key) and self._root[key].has_key(subkey):
            return self._root[key][subkey]
        elif self._default_root.has_key(key) and self._default_root[key].has_key(subkey):
            return self._default_root[key][subkey]
        else:
            return default_value

class AppCheckException(Exception):
    pass

class AppCheck:
    def __init__(self, node):
        self.name = node["name"]
        self.conf = node.get("conf", {})

        try:
            check_module_name = node["check_module"]
        except KeyError:
            check_module_name = self.name

        try:
            check_module = imp.load_source('checksd_%s' % self.name, os.path.join(CHECKS_DIRECTORY, check_module_name + ".py"))
        except Exception:
            traceback_message = traceback.format_exc().strip().replace("\n", " -> ")
            raise AppCheckException('Unable to import check module %s.py from checks.d: %s' % (check_module_name, traceback_message))

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
            raise AppCheckException('Unable to find AgentCheck class for %s' % check_module_name)
        else:
            self.check_class = check_class

    def __repr__(self):
        return "AppCheck(name=%s, conf=%s, check_class=%s" % (self.name, repr(self.conf), repr(self.check_class))

class AppCheckInstance:
    try:
        MYMNT = os.open("%s/proc/self/ns/mnt" % SYSDIG_HOST_ROOT, os.O_RDONLY)
        MYMNT_INODE = os.stat("%s/proc/self/ns/mnt" % SYSDIG_HOST_ROOT).st_ino
        MYNET = os.open("%s/proc/self/ns/net" % SYSDIG_HOST_ROOT, os.O_RDONLY)
        CONTAINER_SUPPORT = True
    except OSError:
        CONTAINER_SUPPORT = False
    TOKEN_PATTERN = re.compile("\{.+\}")
    INIT_CONFIG = {
        "threads_count": 1 # needed by tcp_check and http_check
    }
    AGENT_CONFIG = {
        "is_developer_mode": False,
        "version": 1.0,
        "hostname": get_hostname()
    }
    PROC_DATA_FROM_TOKEN = {
        "port": lambda p: p["ports"][0],
        "port.high": lambda p: p["ports"][-1],
    }
    def __init__(self, check, proc_data):
        self.name = check.name
        self.pid = proc_data["pid"]
        self.vpid = proc_data["vpid"]
        self.check_instance = check.check_class(self.name, self.INIT_CONFIG, self.AGENT_CONFIG)
        
        if self.CONTAINER_SUPPORT:
            try:
                mntns_inode = os.stat(build_ns_path(self.pid, "mnt")).st_ino
                self.is_on_another_container = (mntns_inode != self.MYMNT_INODE)
            except OSError as ex:
                raise AppCheckException(ex.message)
        else:
            self.is_on_another_container = False

        # Add some default values to instance conf, from process data
        self.instance_conf = {
            "host": "localhost",
            "name": self.name,
            "ports": proc_data["ports"]
        }
        if len(proc_data["ports"]) > 0:
            self.instance_conf["port"] = proc_data["ports"][0]

        for key, value in check.conf.items():
            if type(value) is str:
                self.instance_conf[key] = self._expand_template(value, proc_data)
            else:
                self.instance_conf[key] = value

        logging.debug("Created instance of check %s with conf: %s", self.name, repr(self.instance_conf))

    def run(self):
        try:
            if self.is_on_another_container:
                # We need to open and close ns on every iteration
                # because otherwise we lock container deletion
                for ns in self.check_instance.NEEDED_NS:
                    nsfd = os.open(build_ns_path(self.pid, ns), os.O_RDONLY)
                    ret = setns(nsfd)
                    os.close(nsfd)
                    if ret != 0:
                        logging.warning("Cannot setns %s to pid: %d", ns, self.pid)
            self.check_instance.check(self.instance_conf)
            return self.check_instance.get_metrics(), self.check_instance.get_service_checks()
        except OSError as ex: # Raised from os.open() or setns()
            raise AppCheckException(ex.message)
        except Exception as ex: # Raised from check run
            traceback_message = traceback.format_exc()
            raise AppCheckException("%s\n%s" % (repr(ex), traceback_message))
        finally:
            if self.is_on_another_container:
                setns(self.MYNET)
                setns(self.MYMNT)

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
        except Exception as ex:
            raise AppCheckException("Cannot expand template for %s and proc_data %s: %s" % (value, repr(proc_data), ex.message))

class Config:
    def __init__(self):
        self._yaml_config = YamlConfig()
        check_confs = self._yaml_config.get_merged_sequence("app_checks")

        # reverse the list because we are mapping them by name and we want that
        # dragent.yaml checks override dragent.default.yaml ones
        # the get_merged_sequence() instead puts them in the opposite order
        check_confs.reverse()

        self.checks = {}
        for c in check_confs:
            try:
                app_check = AppCheck(c)
                self.checks[app_check.name] = app_check
            except (Exception, IOError) as ex:
                logging.error("Configuration error for check %s: %s", repr(c), ex.message)
    
    def log_level(self):
        level = self._yaml_config.get_single("log", "file_priority", "info")
        if level == "error":
            return logging.ERROR
        elif level == "warning":
            return logging.WARNING 
        elif level == "info":
            return logging.INFO
        elif level == "debug":
            return logging.DEBUG

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
        except ValueError as ex:
            logging.error("Cannot send: %s, size=%dB" % (ex.message, len(msg)))
            return False

    def receive(self, timeout=1):
        message, _ = self.queue.receive(timeout)
        return message

    def __del__(self):
        if hasattr(self, "queue") and self.queue:
            self.close()

class Application:
    KNOWN_INSTANCES_CLEANUP_TIMEOUT = timedelta(minutes=10)
    APP_CHECK_EXCEPTION_RETRY_TIMEOUT = timedelta(minutes=1)
    def __init__(self):
        # Configure only format first because may happen that config file parsing fails and print some logs
        self.config = Config()
        logging.basicConfig(format='%(process)s:%(levelname)s:%(message)s', level=self.config.log_level())
        logging.debug("Check config: %s", repr(self.config.checks))
        # requests generates too noise on information level
        logging.getLogger("requests").setLevel(logging.WARNING)
        self.known_instances = {}
        self.last_known_instances_cleanup = datetime.now()
        self.inqueue = PosixQueue("/sdchecks", PosixQueueType.RECEIVE)
        self.outqueue = PosixQueue("/dragent_app_checks", PosixQueueType.SEND)
        self.blacklisted_pids = set()
        self.last_blacklisted_pids_cleanup = datetime.now()

    def cleanup(self):
        self.inqueue.close()
        self.outqueue.close()

    def clean_known_instances(self, last_request_pids):
        for key in self.known_instances.keys():
            if not key in last_request_pids:
                del self.known_instances[key]

    def main(self):
        logging.info("Starting")
        logging.info("Container support: %s", str(AppCheckInstance.CONTAINER_SUPPORT))
        while True:
            command_s = self.inqueue.receive(None)
            response_body = []
            #print "Received command: %s" % command_s
            command = json.loads(command_s)
            processes = command["body"]
            for p in processes:
                pid = int(p["pid"])
                if pid in self.blacklisted_pids:
                    logging.debug("Process with pid=%d is blacklisted", pid)
                    continue

                try:
                    check_instance = self.known_instances[pid]
                except KeyError:
                    try:
                        check_conf = self.config.checks[p["check"]]
                    except KeyError:
                        logging.error("Cannot find check configuration for name: %s", p["check"])
                        continue
                    try:
                        check_instance = AppCheckInstance(check_conf, p)
                    except AppCheckException as ex:
                        logging.error("Exception on creating check %s: %s", check_conf.name, ex.message)
                        self.blacklisted_pids.add(pid)
                        continue
                    self.known_instances[pid] = check_instance
                
                metrics = []
                service_checks = []
                try:
                    metrics, service_checks = check_instance.run()
                except AppCheckException as ex:
                    logging.error("Exception on running check %s: %s", check_instance.name, ex.message)
                    self.blacklisted_pids.add(pid)
                response_body.append({ "pid": pid,
                                        "display_name": check_instance.name,
                                                 "metrics": metrics,
                                   "service_checks": service_checks})
            response = {
                "id": command["id"],
                "body": response_body
            }
            response_s = json.dumps(response)
            logging.debug("Response size is %d" % len(response_s))
            self.outqueue.send(response_s)
            if datetime.now() - self.last_known_instances_cleanup > self.KNOWN_INSTANCES_CLEANUP_TIMEOUT:
                self.clean_known_instances([p["pid"] for p in processes])
                self.last_known_instances_cleanup = datetime.now()
            if datetime.now() - self.last_blacklisted_pids_cleanup > self.APP_CHECK_EXCEPTION_RETRY_TIMEOUT:
                self.blacklisted_pids.clear()
                self.last_blacklisted_pids_cleanup = datetime.now()
