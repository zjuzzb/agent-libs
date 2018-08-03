#!/usr/bin/env python

import os
import sys
import getopt
import datetime

import jinja2

def usage():
    print 'usage: %s [-i|--image <image>] [-r|--repo] [-a|--agent-version <version>]' % sys.argv[0]
    print '     --image: Can be one of "agent", "kmodule", "agent-slim", or "local" (agent, but using local debian package) '
    print '     --repo: Can be one of "dev", "stable", "rc" '
    print '     --agent-version: set the agent version directly in the image instead '
    print '                      of extracting from dragent binary'
    sys.exit(1)

try:
    opts, args = getopt.getopt(sys.argv[1:],"i:r:a:",["image=", "repo=", "agent-version="])
except getopt.GetoptError:
    usage()

image = ""
repo = ""
agent_version = ""

for opt, arg in opts:
    if opt in ("-i", "--image"):
        image = arg
    if opt in ("-r", "--repo"):
        repo = arg
    if opt in ("-a", "--agent-version"):
        agent_version = arg
#
# Parse arguments
#
if (image == "" or repo == "") and len(args) < 1:
    usage()

p = {}

if image == "agent":
    p['base_docker_image'] = "debian:unstable"
    p['sysdig_repository'] = repo
    p['include_agent_package'] = "apt"
    p['build_kernel_module'] = 1
    p['jdk_debian_release'] = "unstable"
    p['launch_dragent'] = 1
elif image == "local":
    p['base_docker_image'] = "debian:unstable"
    p['sysdig_repository'] = repo
    p['include_agent_package'] = "local"
    p['build_kernel_module'] = 1
    p['jdk_debian_release'] = "unstable"
    p['launch_dragent'] = 1
elif image == "agent-slim":
    p['base_docker_image'] = "bitnami/minideb:jessie"
    p['sysdig_repository'] = repo
    p['include_agent_package'] = "apt"
    p['build_kernel_module'] = 0
    p['jdk_debian_release'] = "jessie-backports"
    p['launch_dragent'] = 1
elif image == "agent-kmodule":
    p['base_docker_image'] = "debian:unstable"
    p['sysdig_repository'] = repo
    p['include_agent_package'] = "apt"
    p['build_kernel_module'] = 1
    p['jdk_debian_release'] = "unstable"
    p['launch_dragent'] = 0

if agent_version != "":
    p['agent_version'] = agent_version

template_str = ""

with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'Dockerfile.jinja2'),'r') as f:
    template_str = f.read()

template = jinja2.Template(template_str, trim_blocks=True)
dockerfile = template.render(p=p)
sys.stdout.write(dockerfile)


