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
import config

# project
from checks import AgentCheck
from util import get_hostname
from config import _is_affirmative

from sysdig_tracers import Tracer

# 3rd party
import yaml
import simplejson as json
import posix_ipc

import requests
from requests.exceptions import ConnectionError
from requests.packages.urllib3.exceptions import (
    SecurityWarning,
    InsecureRequestWarning
)

RLIMIT_MSGQUEUE = 12
# %s will be replaced by the install prefix
CHECKS_DIRECTORY = "%s/lib/python/checks.d"
CUSTOM_CHECKS_DIRECTORY = "%s/lib/python/checks.custom.d"
GLOBAL_PERCENTILES = []

DONT_SEND_LOG_REPORT = 19
SIGHUP_HANDLER_EXIT_CODE = DONT_SEND_LOG_REPORT

try:
    SYSDIG_HOST_ROOT = os.environ["SYSDIG_HOST_ROOT"]
except KeyError:
    SYSDIG_HOST_ROOT = ""

_LIBC = ctypes.CDLL('libc.so.6', use_errno=True)
__NR_setns = 308

# This handler is triggered when sdchecks has stalled
def sighup_handler(signum, frame):
    logging.warning("Received signal %d, dumping stack and exiting with code %d" %
                    (signum, SIGHUP_HANDLER_EXIT_CODE))
    # Extracting stack so that it can be dumped using logging
    for filename, linenumber, funcname, line in traceback.extract_stack(frame):
        if line:
            logging.warning("File: \"%s\", line %d, in %s -> %s" %
                            (filename, linenumber, funcname, line))
        else:
            logging.warning("File: \"%s\", line %d, in %s" %
                            (filename, linenumber, funcname))
    os._exit(SIGHUP_HANDLER_EXIT_CODE)

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

    def get_single(self, key, subkey=None, subsubkey=None, default_value=None):
        for root in self._roots:
            if not root.has_key(key): 
                continue

            value = root[key]
            if subkey is None:
                return value

            if not value.has_key(subkey):
                continue

            subvalue = value[subkey]
            if subsubkey is None: 
                return subvalue

            if not subvalue.has_key(subsubkey):
                continue

            return subvalue[subsubkey]

        return default_value

class AppCheckException(Exception):
    pass

class AppCheckDontRetryException(AppCheckException):
    pass

def _load_check_module(name, module_name, directory):
    try:
        return imp.load_source('checksd_%s' % name, os.path.join(directory, module_name + ".py"))
    except IOError:
        raise
    except Exception:
        traceback_message = traceback.format_exc().strip().replace("\n", " -> ")
        raise AppCheckException('Unable to import check module %s.py from %s: %s' % (module_name, directory, traceback_message))

def _load_check_class(check_module_name, install_prefix):
    try:
        check_module = _load_check_module(check_module_name, check_module_name, CUSTOM_CHECKS_DIRECTORY % install_prefix)
    except IOError:
        try:
            check_module = _load_check_module(check_module_name, check_module_name, CHECKS_DIRECTORY % install_prefix)
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
def get_check_class(check_name, install_prefix, LOADED_CHECKS={}):
    try:
        return LOADED_CHECKS[check_name]
    except KeyError:
        check_class = _load_check_class(check_name, install_prefix)
        LOADED_CHECKS[check_name] = check_class
        return check_class

def detect_root(mntns):
    # When running inside a chroot jail (ex, rkt fly pod)
    # by running setns(mntns) the process escapes the jail
    # since setns will reset the root
    #
    # We need to know which is our root to proper go back to it
    # To do this we are using this trick:
    # 1. setns(mymntns)
    # 2. read /proc/<parent_pid>/root link
    # 3. chroot inside the jail
    # Assuming that our parent will still be in the jail
    ret = setns(mntns)
    if ret != 0:
        logging.error("Error while calling setns")
        sys.exit(1)
    try:
        root = os.readlink("/proc/%d/root" % os.getppid())
        if root != "/":
            os.chroot(root)
            os.chdir("/")
        return root
    except OSError as ex:
        logging.error("Error while setting root: %s" % str(ex))
        sys.exit(1)

class AppCheckInstance:
    try:
        MYMNT = os.open("%s/proc/self/ns/mnt" % SYSDIG_HOST_ROOT, os.O_RDONLY)
        MYROOT = detect_root(MYMNT)
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
        "api_key": "",
        "histogram_percentiles": []
    }
    INIT_CONFIG = {}
    PROC_DATA_FROM_TOKEN = {
        "port": lambda p: p["ports"][0],
        "port.high": lambda p: p["ports"][-1],
    }
    def __init__(self, check, proc_data, install_prefix):
        self.name = check["name"]
        self.pid = proc_data["pid"]
        self.vpid = proc_data["vpid"]
        self.conf_vals = proc_data["conf_vals"]
        self.interval = timedelta(seconds=check.get("interval", 1))
        self.proc_data = proc_data
        self.retry = _is_affirmative(check.get("retry", True))
        self.install_prefix = install_prefix

        try:
            check_module = check["check_module"]
        except KeyError:
            check_module = self.name
        self.AGENT_CONFIG["histogram_percentiles"] = GLOBAL_PERCENTILES
        self.AGENT_CONFIG["install_prefix"] = install_prefix
        self.check_instance = get_check_class(check_module, self.install_prefix)(self.name, self.INIT_CONFIG, self.AGENT_CONFIG)

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
        if proc_data.has_key("solr_port"):
            self.instance_conf["solr_port"] = proc_data["solr_port"]
        else:
            if len(proc_data["ports"]) > 0:
                self.instance_conf["port"] = proc_data["ports"][0]

        for key, value in check.get("conf", {}).items():
            if isinstance(value, (str, unicode)):
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
        except AppCheckDontRetryException as ex:
            logging.info("Skip retries for Prometheus error: %s", str(ex))
            self.retry = False
            saved_ex = ex

        except Exception as ex: # Raised from check run
            traceback_message = traceback.format_exc()
            saved_ex = AppCheckException("%s\n%s" % (repr(ex), traceback_message))
        finally:
            for nsfd in ns_fds:
                os.close(nsfd)
            if self.is_on_another_container:
                setns(self.MYNET)
                setns(self.MYMNT)
                if self.MYROOT != "/":
                    try:
                        os.chroot(self.MYROOT)
                        os.chdir("/")
                    except OSError as ex:
                        logging.error("Error while setting root: %s" % str(ex))
                        sys.exit(1)
                setns(self.MYUTS)
            # We don't need them, but this method clears them so we avoid memory growing
            self.check_instance.get_events()
            self.check_instance.get_service_metadata()

            # Return metrics and checks instead
            return self.check_instance.get_metrics(), self.check_instance.get_service_checks(), saved_ex

    def _expand_template(self, value, proc_data, conf_vals):
        try:
            logging.debug("Expanding template: %s" % repr(value))
            ret = ""
            lastpos = 0
            for token_pos in re.finditer(self.TOKEN_PATTERN, value):
                ret += value[lastpos:token_pos.start()]
                lastpos = token_pos.end()
                token = value[token_pos.start()+1:token_pos.end()-1]
                found_in, token_val = "", ""
                # First try to replace templated values from conf_vals
                if token in conf_vals:
                    token_val, found_in = str(conf_vals[token]), "conf_vals"
                elif token in self.AGENT_CONFIG:
                    # try from agent config
                    token_val, found_in = str(self.AGENT_CONFIG[token]), "agent_config"
                else:
                    # Then try from the per-process data. It will throw an exception if not found.
                    token_val, found_in = str(self.PROC_DATA_FROM_TOKEN[token](proc_data)), "proc_data"
                logging.debug("Resolved token: %s to value: %s found in %s" %
                              (token, token_val, found_in))
                ret += token_val
            ret += value[lastpos:len(value)]
            if ret.isdigit():
                ret = int(ret)
            return ret
        except Exception as ex:
            raise AppCheckException("Cannot expand template for %s, proc_data %s, and conf_vals %s: %s" % (value, repr(proc_data), repr(conf_vals), ex))

class Config:
    def __init__(self, install_prefix):
	self.install_prefix = install_prefix
        etcdir = install_prefix + "/etc"
        self._yaml_config = YamlConfig([os.path.join(etcdir, "dragent.yaml"),
                                        os.path.join(etcdir, "kubernetes/config/dragent.yaml"),
                                        os.path.join(etcdir, "dragent.auto.yaml"),
                                        os.path.join(etcdir, "dragent.default.yaml")])

    def log_level(self):
        level = self._yaml_config.get_single("log", "file_priority", None, "info")
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

    def set_percentiles(self):
        global GLOBAL_PERCENTILES
        percentiles = self._yaml_config.get_single("percentiles")
        if not percentiles is None:
            configstr = ''
            first = True
            for pct in percentiles:
                if not first:
                    configstr += ','
                configstr += str(float(pct) / 100.0)
                first = False
                GLOBAL_PERCENTILES = config.get_histogram_percentiles(configstr)

    def ignore_ssl_warnings(self):
        return bool(self._yaml_config.get_single("app_checks_ignore_ssl_warnings"))

    def watchdog(self):
        timeout = self._yaml_config.get_single("watchdog", 
                                               "subprocesses_timeout_s", 
                                               "sdchecks", 
                                               "60") # This should match the default
                                                     # in dragent/configuration.cpp
        return int(timeout)

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

def prepare_prom_check(pc, port):
    # print "port:", port
    options = pc.get("options")
    use_https = _is_affirmative(options.get("use_https", False) if options else False)
    host = "localhost"
    if options and options.get("host") != None:
        host = options["host"]
    path = pc.get("path", "/metrics");
    if len(path) > 0 and path[0] != '/':
        path = "/" + path
    newconf = {"url": ("https" if use_https else "http") + "://" + host + ":" + str(port) + path}
    if pc.get("max_metrics") != None:
        newconf["max_metrics"] = pc["max_metrics"]
    if pc.get("max_tags") != None:
        newconf["max_tags"] = pc["max_tags"]
    if pc.get("histograms") != None:
        newconf["histograms"] = pc["histograms"]
    if options and options.get("ssl_verify") != None:
        newconf["ssl_verify"] = _is_affirmative(options["ssl_verify"])
    newcheck = {
        "check_module": "prometheus",
        "log_errors": pc.get("log_errors", True),
        "interval": pc.get("interval", 1),
        "conf": newconf,
        "name": "prometheus." + str(port)
    }
    newproc = {
        "check": newcheck,
        "pid": pc["pid"],
        "ports": [port],
        "vpid": pc["vpid"],
        "conf_vals": {}
    }
    return newcheck, newproc

class Application:
    KNOWN_INSTANCES_CLEANUP_TIMEOUT = timedelta(minutes=10)
    APP_CHECK_EXCEPTION_RETRY_TIMEOUT = timedelta(minutes=30)
    def __init__(self, install_prefix):
        self.config = Config(install_prefix)
        logging.basicConfig(format='%(process)s:%(levelname)s:%(message)s', level=self.config.log_level())
        # logging.debug("Check config: %s", repr(self.config.checks))
        # requests generates too noise on information level
        logging.getLogger("requests").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("kazoo.client").setLevel(logging.WARNING)
        self.known_instances = {}
        self.last_known_instances_cleanup = datetime.now()
        self.last_heartbeat = datetime(2010, 1, 1, 0, 0, 0);
        self.heartbeat_min = timedelta(0);

        self.inqueue = PosixQueue("/sdc_app_checks_in", PosixQueueType.RECEIVE, 1)
        self.outqueue = PosixQueue("/sdc_app_checks_out", PosixQueueType.SEND, 1)

        if self.config.ignore_ssl_warnings():
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            requests.packages.urllib3.disable_warnings(SecurityWarning)

        # Blacklist works in two ways
        # 1. for pid+name where we cannot create an AppCheckInstance, skip them
        # 2. for pid+name when AppCheckInstance.run raises exception, run them but don't print errors
        # We need the latter because a check can create checks or metrics even if it raises
        # exceptions
        self.blacklisted_pidnames = set()
        self.last_blacklisted_pidnames_cleanup = datetime.now()

        self.last_request_pidnames = set()

    def cleanup(self):
        self.inqueue.close()
        self.outqueue.close()

    def clean_known_instances(self):
        for key in self.known_instances.keys():
            if not key in self.last_request_pidnames:
                del self.known_instances[key]

    def heartbeat(self, pid, force=False):

        now = datetime.now()

        # Only send heartbeat if enough time has passed
        if ((not force) and (self.last_heartbeat + self.heartbeat_min > now)): return

        # Send heartbeat
        self.last_heartbeat = now;
        ru = resource.getrusage(resource.RUSAGE_SELF)
        sys.stderr.write("HB,%d,%d,%s\n" % (pid, ru.ru_maxrss, now.strftime("%s")))
        sys.stderr.flush()

        # Update the heartbeat_min to half of the watchdog from the config file
        self.heartbeat_min = timedelta(seconds=(self.config.watchdog() / 2))

    def run_check(self, response_body, pidname, check, conf, trc):
        self.last_request_pidnames.add(pidname)
        log_errors = _is_affirmative(check.get("log_errors", True))

        try:
            check_instance = self.known_instances[pidname]
            if check_instance.proc_data != conf:
                # The configuration for this check has changed. Remove it
                # and try to access it again, which triggers the KeyError
                # and lets the exception handler recreate the AppCheckInstance.
                logging.debug("Recreating check %s as definition has changed from \"%s\" to \"%s\"",
                              conf["check"].get("name", "N/A"),
                              str(check_instance.proc_data), str(conf))
                del self.known_instances[pidname]
                check_instance = self.known_instances[pidname]

        except KeyError:
            if pidname in self.blacklisted_pidnames:
                logging.debug("Process with pid=%d,name=%s is blacklisted", pidname[0], pidname[1])
                return False, 0
            logging.debug("Requested check %s", repr(check))

            try:
                check_instance = AppCheckInstance(check, conf, self.config.install_prefix)
            except AppCheckException as ex:
                if log_errors:
                    logging.error("Exception on creating check %s: %s", check["name"], ex)
                self.blacklisted_pidnames.add(pidname)
                return False, 0
            self.known_instances[pidname] = check_instance

        if pidname in self.blacklisted_pidnames and not check_instance.retry:
            logging.debug("Not retrying appcheck " + check_instance.name)
            return False, 0

        trc2 = trc.span(check_instance.name)
        trc2.start(trc2.tag, args={"check_name": check_instance.name,
            "pid":str(check_instance.pid),
            "other_container":str(check_instance.is_on_another_container)})
        metrics, service_checks, ex = check_instance.run()
        # print "check", check_instance.name, "pid", check_instance.pid, "metrics", metrics, "exceptions", type(ex), ":", ex
        nm = len(metrics) if metrics else 0
        trc2.stop(args={"metrics": nm, "exception": "yes" if ex else "no"})

        if ex and pidname not in self.blacklisted_pidnames:
            if log_errors:
                logging.error("Exception on running check %s: %s", check_instance.name, ex)
            self.blacklisted_pidnames.add(pidname)

        expiration_ts = datetime.now() + check_instance.interval
        response_body.append({"pid": pidname[0],
                              "display_name": check_instance.name,
                              "metrics": metrics,
                              "service_checks": service_checks,
                              "expiration_ts": int(expiration_ts.strftime("%s"))})
        return True, nm

    def handle_command(self, command_s, pid):
        appcheck_resp = []
        promcheck_resp = []
        #print "Received command: %s" % command_s
        command = json.loads(command_s)
        #processes = json.loads(command_s)
        processes = command["processes"]
        promchecks = command["prometheus"]
        #print promchecks
        self.last_request_pidnames.clear()
        trc = Tracer()
        trc.start("checks")
        numchecks = 0
        numrun = 0
        nummetrics = 0

        # Create app_checks for prometheus
        for pc in promchecks:
            for port in pc["ports"]:
                newcheck, newproc = prepare_prom_check(pc, port)
                pidname = (newproc["pid"],newcheck["name"])
                ran, nm = self.run_check(promcheck_resp, pidname, newcheck, newproc, trc)
                if ran:
                    numrun += 1
                nummetrics += nm
                self.heartbeat(pid);

        for p in processes:
            numchecks += 1
            check = p["check"]
            pidname = (p["pid"],check["name"])
            ran, nm = self.run_check(appcheck_resp, pidname, check, p, trc)
            if ran:
                numrun += 1
            nummetrics += nm
            self.heartbeat(pid);

        trc.stop(args={"total_metrics": nummetrics, "checks_run": numrun,
            "checks_total": numchecks})
        response_body = {
            "processes": appcheck_resp,
            "prometheus": promcheck_resp
        }
        response_s = json.dumps(response_body)
        logging.debug("Response size is %d", len(response_s))
        self.outqueue.send(response_s)

    def main_loop(self):
        pid = os.getpid()
        while True:
            # Handle received message
            command_s = self.inqueue.receive(1)
            if command_s:
                self.handle_command(command_s, pid)

            # Do some cleanup
            now = datetime.now()
            if now - self.last_known_instances_cleanup > self.KNOWN_INSTANCES_CLEANUP_TIMEOUT:
                self.clean_known_instances()
                self.last_known_instances_cleanup = datetime.now()
            if now - self.last_blacklisted_pidnames_cleanup > self.APP_CHECK_EXCEPTION_RETRY_TIMEOUT:
                self.blacklisted_pidnames.clear()
                self.last_blacklisted_pidnames_cleanup = datetime.now()

            # Always send heartbeat
            self.heartbeat(pid, True)

    def main(self):
        logging.info("Starting")
        # The following message was provided to Goldman Sachs (Oct 2018). Do not change.
        logging.info("Container support: %s", str(AppCheckInstance.CONTAINER_SUPPORT))
        self.config.set_percentiles()
        logging.debug("sdchecks percentiles: %s", str(GLOBAL_PERCENTILES))
        if len(sys.argv) > 1:
            if sys.argv[1] == "runCheck":
                proc_data = {
                    "check": sys.argv[2],
                    "pid": int(sys.argv[3]),
                    "vpid": int(sys.argv[4]) if len(sys.argv) >= 5 else 1,
                    "ports": [int(sys.argv[5]), ] if len(sys.argv) >= 6 else [],
                    "conf_vals": ast.literal_eval(sys.argv[6]) if len(sys.argv) >= 7 else {}
                }
                if sys.argv[2] == "prometheus":
                    check_conf, proc_data = prepare_prom_check(proc_data["conf_vals"], int(sys.argv[5]))
                else:
                    check_conf = self.config.check_conf_by_name(proc_data["check"])
                logging.info("Run AppCheck for %s", proc_data)
                if check_conf is None:
                    print "Check conf not found"
                    sys.exit(1)
                else:
                    print("Using check conf: %s" % repr(check_conf))
                check_instance = AppCheckInstance(check_conf, proc_data, self.config.install_prefix)
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
            signal.signal(signal.SIGHUP, sighup_handler)
            self.main_loop()
