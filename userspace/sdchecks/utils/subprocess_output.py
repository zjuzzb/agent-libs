# stdlib
from future.utils import bytes_to_native_str
from functools import wraps
import logging
import subprocess
import tempfile

# project
from utils.platform import Platform

log = logging.getLogger(__name__)


# FIXME: python 2.7 has a far better way to do this
def get_subprocess_output(command, log, shell=False, stdin=None):
    """
    Run the given subprocess command and return it's output. Raise an Exception
    if an error occurs.
    """

    # Use tempfile, allowing a larger amount of memory. The subprocess.Popen
    # docs warn that the data read is buffered in memory. They suggest not to
    # use subprocess.PIPE if the data size is large or unlimited.
    with tempfile.TemporaryFile() as stdout_f, tempfile.TemporaryFile() as stderr_f:
        proc = subprocess.Popen(command,
                                shell=shell,
                                stdin=stdin,
                                stdout=stdout_f,
                                stderr=stderr_f)
        proc.wait()
        stderr_f.seek(0)
        err = bytes_to_native_str(stderr_f.read())
        if err:
            log.debug("Error while running {0} : {1}".format(" ".join(command),
                                                             repr(err)))

        stdout_f.seek(0)
        output = bytes_to_native_str(stdout_f.read())
    return (output, err, proc.returncode)


def log_subprocess(func):
    """
    Wrapper around subprocess to log.debug commands.
    """
    @wraps(func)
    def wrapper(*params, **kwargs):
        fc = "%s(%s)" % (func.__name__, ', '.join(
            [a.__repr__() for a in params] +
            ["%s = %s" % (a, b) for a, b in list(kwargs.items())]
        ))
        log.debug("%s called" % fc)
        return func(*params, **kwargs)
    return wrapper

subprocess.Popen = log_subprocess(subprocess.Popen)
