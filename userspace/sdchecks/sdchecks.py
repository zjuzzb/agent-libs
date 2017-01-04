# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring, line-too-long
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
import sys
import signal
import ast

# project
from checks import AgentCheck
from util import get_hostname

# 3rd party
import yaml
import simplejson as json
import posix_ipc

RLIMIT_MSGQUEUE = 12
CHECKS_DIRECTORY = "/opt/draios/lib/python/checks.d"
CUSTOM_CHECKS_DIRECTORY = "/opt/draios/lib/python/checks.custom.d"

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
    def __init__(self, paths):
        self._roots = []
        for path in paths:
            try:
                with open(path, "r") as config_file:
                    self._roots.append(yaml.load(config_file.read()))
            except IOError as ex:
                # Cannot use logging because it's not initialized yet
                sys.stderr.write("%d:DEBUG:Cannot read config file %s: %s\n" % (os.getpid(), path, ex))
            except Exception as ex:
                sys.stderr.write("%d:ERROR:Cannot parse config file %s: %s\n" % (os.getpid(), path, ex))

    def get_merged_sequence(self, key, default=None):
        ret = default
        if ret is None:
            ret = []
        for root in self._roots:
            if root.has_key(key):
                try:
                    ret += root[key]
                except TypeError as ex:
                    logging.error("Cannot parse config correctly, \"%s\" is not a list, exception=%s" % (key, str(ex)))
        return ret

    def get_single(self, key, subkey, default_value=None):
        # TODO: now works only for key.subkey, more general implementation may be needed
        for root in self._roots:
            if root.has_key(key) and root[key].has_key(subkey):
                return root[key][subkey]
        return default_value

class AppCheckException(Exception):
    pass

def _load_check_module(name, module_name, directory):
    try:
        return imp.load_source('checksd_%s' % name, os.path.join(directory, module_name + ".py"))
    except IOError:
        raise
    except Exception:
        traceback_message = traceback.format_exc().strip().replace("\n", " -> ")
        raise AppCheckException('Unable to import check module %s.py from %s: %s' % (module_name, directory, traceback_message))

def _load_check_class(check_module_name):
    try:
        check_module = _load_check_module(check_module_name, check_module_name, CUSTOM_CHECKS_DIRECTORY)
    except IOError:
        try:
            check_module = _load_check_module(check_module_name, check_module_name, CHECKS_DIRECTORY)
        except IOError as ex:
            raise AppCheckException('Unable to find AgentCheck class for %s reason=%s' % (check_module_name, str(ex)))

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
        return check_class

# LOADED_CHECKS acts as a static store for
# check classes already loaded
def get_check_class(check_name, LOADED_CHECKS={}):
    try:
        return LOADED_CHECKS[check_name]
    except KeyError:
        check_class = _load_check_class(check_name)
        LOADED_CHECKS[check_name] = check_class
        return check_class

class AppCheckInstance:
    try:
        MYMNT = os.open("%s/proc/self/ns/mnt" % SYSDIG_HOST_ROOT, os.O_RDONLY)
        MYMNT_INODE = os.stat("%s/proc/self/ns/mnt" % SYSDIG_HOST_ROOT).st_ino
        MYNET = os.open("%s/proc/self/ns/net" % SYSDIG_HOST_ROOT, os.O_RDONLY)
        MYUTS = os.open("%s/proc/self/ns/uts" % SYSDIG_HOST_ROOT, os.O_RDONLY)
        CONTAINER_SUPPORT = True
    except OSError:
        CONTAINER_SUPPORT = False
    TOKEN_PATTERN = re.compile("\{.+?\}")
    AGENT_CONFIG = {
        "is_developer_mode": False,
        "version": 1.0,
        "hostname": get_hostname(),
        "api_key": ""
    }
    INIT_CONFIG = {}
    PROC_DATA_FROM_TOKEN = {
        "port": lambda p: p["ports"][0],
        "port.high": lambda p: p["ports"][-1],
    }
    def __init__(self, check, proc_data):
        self.name = check["name"]
        self.pid = proc_data["pid"]
        self.vpid = proc_data["vpid"]
        self.conf_vals = proc_data["conf_vals"]
        self.interval = timedelta(seconds=check.get("interval", 1))

        try:
            check_module = check["check_module"]
        except KeyError:
            check_module = self.name
        self.check_instance = get_check_class(check_module)(self.name, self.INIT_CONFIG, self.AGENT_CONFIG)

        if self.CONTAINER_SUPPORT:
            mnt_ns_path = build_ns_path(self.pid, "mnt")
            try:
                mntns_inode = os.stat(mnt_ns_path).st_ino
                self.is_on_another_container = (mntns_inode != self.MYMNT_INODE)
            except OSError as ex:
                raise AppCheckException("stat failed on %s: %s" % (mnt_ns_path, repr(ex)))
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

        for key, value in check.get("conf", {}).items():
            if isinstance(value, str):
                self.instance_conf[key] = self._expand_template(value, proc_data, self.conf_vals)
            else:
                self.instance_conf[key] = value

        logging.debug("Created instance of check %s with conf: %s", self.name, repr(self.instance_conf))

    def run(self):
        saved_ex = None
        ns_fds = []
        try:
            if self.is_on_another_container:
                # We need to open and close ns on every iteration
                # because otherwise we lock container deletion
                for ns in self.check_instance.NEEDED_NS:
                    nsfd = os.open(build_ns_path(self.pid, ns), os.O_RDONLY)
                    ns_fds.append(nsfd)
                for nsfd in ns_fds:
                    ret = setns(nsfd)
                    if ret != 0:
                        raise OSError("Cannot setns to pid: %d" % self.pid)
            self.check_instance.check(self.instance_conf)
        except Exception as ex: # Raised from check run
            traceback_message = traceback.format_exc()
            saved_ex = AppCheckException("%s\n%s" % (repr(ex), traceback_message))
        finally:
            for nsfd in ns_fds:
                os.close(nsfd)
            if self.is_on_another_container:
                setns(self.MYNET)
                setns(self.MYMNT)
                setns(self.MYUTS)
            # We don't need them, but this method clears them so we avoid memory growing
            self.check_instance.get_events()
            self.check_instance.get_service_metadata()

            # Return metrics and checks instead
            return self.check_instance.get_metrics(), self.check_instance.get_service_checks(), saved_ex

    def _expand_template(self, value, proc_data, conf_vals):
        try:
            ret = ""
            lastpos = 0
            for token in re.finditer(self.TOKEN_PATTERN, value):
                ret += value[lastpos:token.start()]
                lastpos = token.end()
                token_key = value[token.start()+1:token.end()-1]
                # First try to replace templated values from conf_vals
                if token_key in conf_vals:
                    ret += str(conf_vals[token_key])
                else:
                    # Then try from the per-process data. It will throw an exception if not found.
                    ret += str(self.PROC_DATA_FROM_TOKEN[token_key](proc_data))
            ret += value[lastpos:len(value)]
            if ret.isdigit():
                ret = int(ret)
            return ret
        except Exception as ex:
            raise AppCheckException("Cannot expand template for %s, proc_data %s, and conf_vals %s: %s" % (value, repr(proc_data), repr(conf_vals), ex))

class Config:
    def __init__(self):
        etcdir = "/opt/draios/etc"
        self._yaml_config = YamlConfig([os.path.join(etcdir, "dragent.yaml"),
                                        os.path.join(etcdir, "dragent.auto.yaml"),
                                        os.path.join(etcdir, "dragent.default.yaml")])

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
        else:
            return logging.INFO

    def check_conf_by_name(self, name):
        checks = self._yaml_config.get_merged_sequence("app_checks")
        for check in checks:
            if check["name"] == name:
                return check
        return None

class PosixQueueType:
    SEND = 0
    RECEIVE = 1

class PosixQueue:
    MSGSIZE = 3 << 20
    MAXMSGS = 3
    MAXQUEUES = 10
    def __init__(self, name, direction, maxmsgs=MAXMSGS):
        limit = self.MAXQUEUES*(self.MAXMSGS+2)*self.MSGSIZE
        resource.setrlimit(RLIMIT_MSGQUEUE, (limit, limit))
        self.direction = direction
        self.queue = posix_ipc.MessageQueue(name, os.O_CREAT, mode=0600,
                                            max_messages=maxmsgs, max_message_size=self.MSGSIZE,
                                            read=(self.direction == PosixQueueType.RECEIVE),
                                            write=(self.direction == PosixQueueType.SEND))

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
            logging.error("Cannot send: %s, size=%dB", ex, len(msg))
            return False

    def receive(self, timeout=1):
        try:
            message, _ = self.queue.receive(timeout)
            return message
        except posix_ipc.SignalError:
            return None
        except posix_ipc.BusyError:
            return None

    def __del__(self):
        if hasattr(self, "queue") and self.queue:
            self.close()

class Application:
    KNOWN_INSTANCES_CLEANUP_TIMEOUT = timedelta(minutes=10)
    APP_CHECK_EXCEPTION_RETRY_TIMEOUT = timedelta(minutes=30)
    def __init__(self):
        self.config = Config()
        logging.basicConfig(format='%(process)s:%(levelname)s:%(message)s', level=self.config.log_level())
        # logging.debug("Check config: %s", repr(self.config.checks))
        # requests generates too noise on information level
        logging.getLogger("requests").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("kazoo.client").setLevel(logging.WARNING)
        self.known_instances = {}
        self.last_known_instances_cleanup = datetime.now()

        self.inqueue = PosixQueue("/sdc_app_checks_in", PosixQueueType.RECEIVE, 1)
        self.outqueue = PosixQueue("/sdc_app_checks_out", PosixQueueType.SEND, 1)

        # Blacklist works in two ways
        # 1. for pids where we cannot create an AppCheckInstance, skip them
        # 2. for pids when AppCheckInstance.run raises exception, run them but don't print errors
        # We need the latter because a check can create checks or metrics even if it raises
        # exceptions
        self.blacklisted_pids = set()
        self.last_blacklisted_pids_cleanup = datetime.now()

        self.last_request_pids = set()

    def cleanup(self):
        self.inqueue.close()
        self.outqueue.close()

    def clean_known_instances(self):
        for key in self.known_instances.keys():
            if not key in self.last_request_pids:
                del self.known_instances[key]

    def handle_command(self, command_s):
        response_body = []
        #print "Received command: %s" % command_s
        processes = json.loads(command_s)
        self.last_request_pids.clear()

        for p in processes:
            pid = p["pid"]
            self.last_request_pids.add(pid)

            try:
                check_instance = self.known_instances[pid]
            except KeyError:
                if pid in self.blacklisted_pids:
                    logging.debug("Process with pid=%d is blacklisted", pid)
                    continue
                check = p["check"]
                logging.debug("Requested check %s", repr(check))

                try:
                    check_instance = AppCheckInstance(check, p)
                except AppCheckException as ex:
                    logging.error("Exception on creating check %s: %s", check["name"], ex)
                    self.blacklisted_pids.add(pid)
                    continue
                self.known_instances[pid] = check_instance

            metrics, service_checks, ex = check_instance.run()

            if ex and pid not in self.blacklisted_pids:
                logging.error("Exception on running check %s: %s", check_instance.name, ex)
                self.blacklisted_pids.add(pid)

            expiration_ts = datetime.now() + check_instance.interval
            response_body.append({"pid": pid,
                                  "display_name": check_instance.name,
                                  "metrics": metrics,
                                  "service_checks": service_checks,
                                  "expiration_ts": int(expiration_ts.strftime("%s"))})
        response_s = json.dumps(response_body)
        logging.debug("Response size is %d", len(response_s))
        self.outqueue.send(response_s)

    def main_loop(self):
        pid = os.getpid()
        while True:
            # Handle received message
            command_s = self.inqueue.receive(1)
            if command_s:
                self.handle_command(command_s)

            # Do some cleanup
            now = datetime.now()
            if now - self.last_known_instances_cleanup > self.KNOWN_INSTANCES_CLEANUP_TIMEOUT:
                self.clean_known_instances()
                self.last_known_instances_cleanup = datetime.now()
            if now - self.last_blacklisted_pids_cleanup > self.APP_CHECK_EXCEPTION_RETRY_TIMEOUT:
                self.blacklisted_pids.clear()
                self.last_blacklisted_pids_cleanup = datetime.now()

            # Send heartbeat
            ru = resource.getrusage(resource.RUSAGE_SELF)
            sys.stderr.write("HB,%d,%d,%s\n" % (pid, ru.ru_maxrss, now.strftime("%s")))
            sys.stderr.flush()

    def main(self):
        logging.info("Starting")
        logging.info("Container support: %s", str(AppCheckInstance.CONTAINER_SUPPORT))
        if len(sys.argv) > 1:
            if sys.argv[1] == "runCheck":
                proc_data = {
                    "check": sys.argv[2],
                    "pid": int(sys.argv[3]),
                    "vpid": int(sys.argv[4]) if len(sys.argv) >= 5 else 1,
                    "ports": [int(sys.argv[5]), ] if len(sys.argv) >= 6 else [],
                    "conf_vals": ast.literal_eval(sys.argv[6]) if len(sys.argv) >= 7 else {}
                }
                logging.info("Run AppCheck for %s", proc_data)
                check_conf = self.config.check_conf_by_name(proc_data["check"])
                if check_conf is None:
                    print "Check conf not found"
                    sys.exit(1)
                else:
                    print("Using check conf: %s" % repr(check_conf))
                check_instance = AppCheckInstance(check_conf, proc_data)
                metrics, service_checks, ex = check_instance.run()
                print "Conf: %s" % repr(check_instance.instance_conf)
                print "Metrics: %s" % repr(metrics)
                print "Checks: %s" % repr(service_checks)
                print "Exception: %s" % ex
            elif sys.argv[1] == "help":
                print "Available commands:"
                print "sdchecks runCheck <checkname> <pid> <vpid> <port> <conf_vals>"
        else:
            # In this mode register our usr1 handler to print stack trace (useful for debugging)
            signal.signal(signal.SIGUSR1, lambda sig, stack: traceback.print_stack(stack))
            self.main_loop()
