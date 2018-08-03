#!/usr/bin/env python

import os
import sys
import getopt
import datetime

import jinja2

def usage():
    print 'usage: %s [-v|--variant <variant>] [-a|--agent-version <version>]' % sys.argv[0]
    print '     --variant: Can be one of "dev", "rc", "stable", "slim", or "agent-kmodule"'
    print '     --agent-version: set the agent version directly in the image instead '
    print '                      of extracting from dragent binary'
    sys.exit(1)

try:
    opts, args = getopt.getopt(sys.argv[1:],"v:a:",["variant=", "agent-version="])
except getopt.GetoptError:
    usage()

variant = ""
agent_version = ""

for opt, arg in opts:
    if opt in ("-v", "--variant"):
        variant = arg
    if opt in ("-a", "--agent-version"):
        agent_version = arg
#
# Parse arguments
#
if variant == "" and len(args) < 1:
    usage()

p = {}

if variant == "stable":
    p['base_docker_image'] = "debian:unstable"
    p['sysdig_repository'] = "stable"
    p['include_agent_package'] = "apt"
    p['build_kernel_module'] = 1
    p['jdk_debian_release'] = "unstable"
    p['launch_dragent'] = 1
elif variant == "rc":
    p['base_docker_image'] = "debian:unstable"
    p['sysdig_repository'] = "rc"
    p['include_agent_package'] = "apt"
    p['build_kernel_module'] = 1
    p['jdk_debian_release'] = "unstable"
    p['launch_dragent'] = 1
elif variant == "dev":
    p['base_docker_image'] = "debian:unstable"
    p['sysdig_repository'] = "dev"
    p['include_agent_package'] = "apt"
    p['build_kernel_module'] = 1
    p['jdk_debian_release'] = "unstable"
    p['launch_dragent'] = 1
elif variant == "local":
    p['base_docker_image'] = "debian:unstable"
    p['sysdig_repository'] = "dev"
    p['include_agent_package'] = "local"
    p['build_kernel_module'] = 1
    p['jdk_debian_release'] = "unstable"
    p['launch_dragent'] = 1
elif variant == "slim":
    p['base_docker_image'] = "bitnami/minideb:jessie"
    p['sysdig_repository'] = "stable"
    p['include_agent_package'] = "apt"
    p['build_kernel_module'] = 0
    p['jdk_debian_release'] = "jessie-backports"
    p['launch_dragent'] = 1
elif variant == "agent-kmodule":
    p['base_docker_image'] = "debian:unstable"
    p['sysdig_repository'] = "stable"
    p['include_agent_package'] = "apt"
    p['build_kernel_module'] = 1
    p['jdk_debian_release'] = "jessie"
    p['launch_dragent'] = 0

if agent_version != "":
    p['agent_version'] = agent_version

template_str = ""

with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'Dockerfile.jinja2'),'r') as f:
    template_str = f.read()

template = jinja2.Template(template_str, trim_blocks=True)
dockerfile = template.render(p=p)
sys.stdout.write(dockerfile)


