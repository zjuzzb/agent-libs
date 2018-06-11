#!/usr/bin/env python

import os
import sys
import argparse
import uuid

from random import randint

SYSCALL_LIST = [
    "accept", "bind", "bpf", "chdir",
    "chmod", "chroot", "clone", "close",
    "connect", "creat", "dup", "eventfd",
    "execve", "fchdir", "fcntl", "fork",
    "getegid", "geteuid", "getgid", "getresgid",
    "getresuid", "getrlimit", "getuid", "inotify",
    "kill", "lchown", "link", "linkat",
    "listen", "mkdir", "mkdirat", "mount",
    "old", "open", "openat", "pipe",
    "pread64", "preadv", "prlimit", "process",
    "ptrace", "pwrite", "pwritev", "quotactl",
    "read", "readv", "recvfrom", "recvmmsg",
    "recvmsg", "rename", "renameat", "rmdir",
    "seccomp", "sendfile", "sendmmsg", "sendmsg",
    "sendto", "setgid", "setresgid", "setresuid",
    "setrlimit", "setuid", "shutdown", "signalfd",
    "socket", "socketpair", "splice", "symlink",
    "symlinkat", "tgkill", "timerfd", "tkill",
    "ugetrlimit", "umount2", "unlink", "unlinkat",
    "vfork", "write", "writev", "<unknown>"
]

PROCESS_LIST = [
    "entrypoint.sh", "top", "ps", "ls", "htop",
    "java", "sh", "docker", "nc", "sshd", "ssh",
    "emacs", "ln"
]

def gen_procs(n):
    ret = set()

    while len(ret) < n:
        if randint(0, 100) < 50:
            ret.add(PROCESS_LIST[randint(0, len(PROCESS_LIST)-1)])
        else:
            ret.add(str(uuid.uuid4())[0:8])

    return ret

def gen_paths(n, l):
    ret = set(l)

    components = (str(uuid.uuid4()) + str(uuid.uuid4())).split("-")
    
    while len(ret) < n:
        depth = randint(3, 6)
        p = "/"
        for i in xrange(0, depth):
            p += components[randint(0, len(components)-1)] + "/"
        ret.add(p[:-1])

    return ret

def gen_syscalls(n):
    ret = set()

    while len(ret) < n:
        ret.add(SYSCALL_LIST[randint(0, len(SYSCALL_LIST)-1)])

    return ret

def gen_listenports(n):
    ret = set()

    while len(ret) < n:
        ret.add(randint(0, 65535))
        n -= 1

    return ret

def fmat(ind, k, v=None):
    if v is None:
        return " "*ind + k + "\n"
    else:
        return " "*ind + k +": \"" + str(v) + "\"\n"

def gen_matchlist(ind, outf, name, values, ofks, rw_values=[]):
    outf.write(fmat(ind, name+"_details {"))
    ind += 2
    outf.write(fmat(ind, "lists {"))
    ind += 2
    if len(rw_values) > 0:
        outf.write(fmat(ind, "fs_access_type: ACCESS_READ"))
    for v in values:
        outf.write(fmat(ind, "values", v))
    outf.write(fmat(ind, "on_match: EFFECT_ACCEPT"))
    ind -= 2
    outf.write(fmat(ind, "}"))
    if len(rw_values) > 0:
        outf.write(fmat(ind, "lists {"))
        ind += 2
        outf.write(fmat(ind, "fs_access_type: ACCESS_WRITE"))
        for v in rw_values:
            outf.write(fmat(ind, "values", v))
        outf.write(fmat(ind, "on_match: EFFECT_ACCEPT"))
        ind -= 2
        outf.write(fmat(ind, "}"))
    outf.write(fmat(ind, "on_default: EFFECT_DENY"))
    for ofk in ofks:
        outf.write(fmat(ind, "output_field_keys", ofk))
    ind -= 2
    outf.write(fmat(ind, "}"))
    return ind

def main(out_file, size):

    ind = 0
    
    with open(out_file, "w") as f:

        while size:
            f.write(fmat(ind, "baseline_list {"))
            ind += 2;

            procs = gen_procs(randint(5, 10))
            r_fs = gen_paths(randint(30, 50), ["/usr/lib", "/bin", "/etc"])
            rw_fs = gen_paths(randint(20, 40), ["/tmp", "/dev/null", "/proc"])
            scalls = gen_syscalls(randint(40, 70))
            ports = gen_listenports(randint(0, 5))

            bid = str(uuid.uuid4())
            bhash = "hash-of-" + bid
            scope_value = bid

            f.write(fmat(ind, "id", bid))
            f.write(fmat(ind, "hash", bhash))
            f.write(fmat(ind, "scope {"))
            ind += 2;
            f.write(fmat(ind, "key", "container.image.name_no_digest"))
            f.write(fmat(ind, "value", scope_value))
            ind -= 2;
            f.write(fmat(ind, "}"))

            f.write(fmat(ind, "matchlist_details {"))
            ind += 2;

            ind = gen_matchlist(ind, f, "process", procs, ["proc.name"])
            ind = gen_matchlist(ind, f, "fs", r_fs, ["fd.name", "proc.name"], rw_fs)
            ind = gen_matchlist(ind, f, "syscall", scalls, ["evt.type"])
            ind = gen_matchlist(ind, f, "listenport", ports, ["fd.sport"])

            ind -= 2;
            f.write(fmat(ind, "}"))
            ind -= 2

            size -= 1

            f.write(fmat(ind, "}"))
    return

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--output", help="output file", type=str, default="./baselines.txt")
    parser.add_argument("-s", "--size", help="how many baselines will be generated", type=int, default=1)
    args = parser.parse_args()
    
    main(args.output, args.size)
