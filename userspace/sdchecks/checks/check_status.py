"""
This module contains classes which are used to occasionally persist the status
of checks.
"""
# stdlib
from collections import defaultdict
import cPickle as pickle
import datetime
import logging
import os
import platform
import sys
import tempfile
import time

# 3p
import ntplib
import yaml

# project
import config
from util import plural
from utils.ntp import get_ntp_args
from utils.pidfile import PidFile
from utils.platform import Platform


STATUS_OK = 'OK'
STATUS_ERROR = 'ERROR'
STATUS_WARNING = 'WARNING'

NTP_OFFSET_THRESHOLD = 60


log = logging.getLogger(__name__)


class Stylizer(object):

    STYLES = {
        'bold'    : 1,
        'grey'    : 30,
        'red'     : 31,
        'green'   : 32,
        'yellow'  : 33,
        'blue'    : 34,
        'magenta' : 35,
        'cyan'    : 36,
        'white'   : 37,
    }

    HEADER = '\033[1m'
    UNDERLINE = '\033[2m'

    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    RESET = '\033[0m'

    ENABLED = False

    @classmethod
    def stylize(cls, text, *styles):
        """ stylize the text. """
        if not cls.ENABLED:
            return text
        # don't bother about escaping, not that complicated.
        fmt = '\033[%dm%s'

        for style in styles or []:
            text = fmt % (cls.STYLES[style], text)

        return text + fmt % (0, '')  # reset


# a small convienence method
def style(*args):
    return Stylizer.stylize(*args)


def logger_info():
    loggers = []
    root_logger = logging.getLogger()
    if len(root_logger.handlers) > 0:
        for handler in root_logger.handlers:
            if isinstance(handler, logging.StreamHandler):
                try:
                    loggers.append(handler.stream.name)
                except AttributeError:
                    loggers.append("unnamed stream")
            if isinstance(handler, logging.handlers.SysLogHandler):
                if isinstance(handler.address, basestring):
                    loggers.append('syslog:%s' % handler.address)
                else:
                    loggers.append('syslog:(%s, %s)' % handler.address)
    else:
        loggers.append("No loggers configured")
    return ', '.join(loggers)


def get_ntp_info():
    req_args = get_ntp_args()
    ntp_offset = ntplib.NTPClient().request(**req_args).offset
    if abs(ntp_offset) > NTP_OFFSET_THRESHOLD:
        ntp_styles = ['red', 'bold']
    else:
        ntp_styles = []
    return ntp_offset, ntp_styles


class AgentStatus(object):
    """
    A small class used to load and save status messages to the filesystem.
    """

    NAME = None

    def __init__(self):
        self.created_at = datetime.datetime.now()
        self.created_by_pid = os.getpid()

    def has_error(self):
        raise NotImplementedError

    def persist(self):
        try:
            path = self._get_pickle_path()
            log.debug("Persisting status to %s" % path)
            f = open(path, 'w')
            try:
                pickle.dump(self, f)
            finally:
                f.close()
        except Exception:
            log.exception("Error persisting status")

    def created_seconds_ago(self):
        td = datetime.datetime.now() - self.created_at
        return td.seconds

    def render(self):
        indent = "  "
        lines = self._header_lines(indent) + [
            indent + l for l in self.body_lines()
        ] + ["", ""]
        return "\n".join(lines)

    @classmethod
    def _title_lines(self):
        name_line = "%s (v %s)" % (self.NAME, config.get_version())
        lines = [
            "=" * len(name_line),
            "%s" % name_line,
            "=" * len(name_line),
            "",
        ]
        return lines

    def _header_lines(self, indent):
        # Don't indent the header
        lines = self._title_lines()
        if self.created_seconds_ago() > 120:
            styles = ['red','bold']
        else:
            styles = []
        # We color it in red if the status is too old
        fields = [
            (
                style("Status date", *styles),
                style("%s (%ss ago)" % (
                    self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                    self.created_seconds_ago()), *styles
                )
            )
        ]

        fields += [
            ("Pid", self.created_by_pid),
            ("Platform", platform.platform()),
            ("Python Version", platform.python_version()),
            ("Logs", logger_info()),
        ]

        for key, value in fields:
            l = indent + "%s: %s" % (key, value)
            lines.append(l)
        return lines + [""]

    def to_dict(self):
        return {
            'pid': self.created_by_pid,
            'status_date': "%s (%ss ago)" % (
                self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                self.created_seconds_ago()
            ),
        }

    @classmethod
    def _not_running_message(cls):
        lines = cls._title_lines() + [
            style("  %s is not running." % cls.NAME, 'red'),
            style("""  You can get more details in the logs:
    %s""" % logger_info(), 'red'),
            "",
            ""
        ]
        return "\n".join(lines)


    @classmethod
    def remove_latest_status(cls):
        log.debug("Removing latest status")
        try:
            os.remove(cls._get_pickle_path())
        except OSError:
            pass

    @classmethod
    def load_latest_status(cls):
        try:
            f = open(cls._get_pickle_path())
            try:
                return pickle.load(f)
            finally:
                f.close()
        except IOError:
            return None

    @classmethod
    def print_latest_status(cls, verbose=False):
        cls.verbose = verbose
        Stylizer.ENABLED = False
        try:
            if sys.stdout.isatty():
                Stylizer.ENABLED = True
        except Exception:
            # Don't worry if we can't enable the
            # stylizer.
            pass

        message = cls._not_running_message()
        exit_code = -1

        module_status = cls.load_latest_status()
        if module_status:
            message = module_status.render()
            exit_code = 0
            if module_status.has_error():
                exit_code = 1

        sys.stdout.write(message)
        return exit_code

    @classmethod
    def _get_pickle_path(cls):
        if os.path.isdir(PidFile.get_dir()):
            path = PidFile.get_dir()
        else:
            path = tempfile.gettempdir()
        return os.path.join(path, cls.__name__ + '.pickle')


class InstanceStatus(object):

    def __init__(self, instance_id, status, error=None, tb=None, warnings=None, metric_count=None,
                 instance_check_stats=None):
        self.instance_id = instance_id
        self.status = status
        if error is not None:
            self.error = repr(error)
        else:
            self.error = None
        self.traceback = tb
        self.warnings = warnings
        self.metric_count = metric_count
        self.instance_check_stats = instance_check_stats

    def has_error(self):
        return self.status == STATUS_ERROR

    def has_warnings(self):
        return self.status == STATUS_WARNING


class CheckStatus(object):

    def __init__(self, check_name, instance_statuses, metric_count=None,
                 event_count=None, service_check_count=None, service_metadata=[],
                 init_failed_error=None, init_failed_traceback=None,
                 library_versions=None, source_type_name=None,
                 check_stats=None):
        self.name = check_name
        self.source_type_name = source_type_name
        self.instance_statuses = instance_statuses
        self.metric_count = metric_count or 0
        self.event_count = event_count or 0
        self.service_check_count = service_check_count or 0
        self.init_failed_error = init_failed_error
        self.init_failed_traceback = init_failed_traceback
        self.library_versions = library_versions
        self.check_stats = check_stats
        self.service_metadata = service_metadata

    @property
    def status(self):
        if self.init_failed_error:
            return STATUS_ERROR
        for instance_status in self.instance_statuses:
            if instance_status.status == STATUS_ERROR:
                return STATUS_ERROR
        return STATUS_OK

    def has_error(self):
        return self.status == STATUS_ERROR


class EmitterStatus(object):

    def __init__(self, name, error=None):
        self.name = name
        self.error = None
        if error:
            self.error = repr(error)

    @property
    def status(self):
        if self.error:
            return STATUS_ERROR
        else:
            return STATUS_OK

    def has_error(self):
        return self.status != STATUS_OK