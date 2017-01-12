#!/usr/bin/python

import os
from tempfile import NamedTemporaryFile
import argparse

agent_start_str = "Information, Agent start"
heap_separator = "---------------------"

base_profile = []
final_profile = []

logfile = "/opt/draios/logs/draios.log"
dragent_bin = "/opt/draios/bin/dragent"
pprof_bin = "/usr/local/bin/pprof"
pprof_arg = "--pdf "

parser = argparse.ArgumentParser(description='Parse agent heap profiling data')
parser.add_argument("logfile", help="path to agent logfile")
parser.add_argument("--dragent_binary", default=dragent_bin, help="path to agent binary")
parser.add_argument("--pprof", default=pprof_bin, help="path to pprof script")
parser.add_argument("--gv", action="store_true", help="display output using gv (req X11)")
parser.add_argument("--plain-text", action="store_true", help="dump output in plain text format")
args = parser.parse_args()

logfile = args.logfile
dragent_bin = args.dragent_binary
pprof_bin = args.pprof
if args.plain_text:
    pprof_arg = "--text "
elif args.gv:
    pprof_arg = "--gv "

with open(logfile, 'r') as f:
    dumping_profile = False
    for line in f:
        if line.rstrip() == heap_separator:
            dumping_profile = not dumping_profile
            if dumping_profile:
                if not base_profile:
                    dump_target = base_profile
                else:
                    final_profile[:] = []
                    dump_target = final_profile
            continue
        elif agent_start_str in line:
            # The agent restarted, clear everything
            dumping_profile = False
            base_profile[:] = []
            final_profile[:] = []

        if dumping_profile:
            dump_target.append(line)

def print_profile(string_list):
    for print_str in string_list:
        print print_str.rstrip()

def write_profile(string_list, outfile):
    # XXX check that outfile is open and writable
    for write_str in string_list:
        outfile.write(write_str)
        
if final_profile:
    with NamedTemporaryFile() as base_file, NamedTemporaryFile() as final_file:
        print "Dumping base memory profile to " + base_file.name
        write_profile(base_profile, base_file)
        print "Dumping last memory profile to " + final_file.name
        write_profile(final_profile, final_file)

        run_str = pprof_bin + " " + pprof_arg + dragent_bin + " --base=" + base_file.name + " " + final_file.name
        if pprof_arg == "--pdf ":
            run_str = run_str + " > /out/heap_profile.pdf"
        print run_str
        os.system(run_str)
else:
    print "no profiling data for the last agent instance"
