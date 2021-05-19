#!/usr/bin/env python

from __future__ import print_function
import os
import sys
import getopt
import jinja2

def usage():
    print('usage: %s [-i|--image <image>] [-r|--repo <repo>] [-t|--template <template>]' % sys.argv[0])
    print('     --image: Can be one of "agent", "agent-kmodule", "agent-slim", "agent-kmodule-thin", or "local" (agent, but using local debian package) ')
    print('     --repo: Can be one of "dev", "stable", "rc" ')
    print('     --template: defaults to Dockerfile.jinja2 ')
    sys.exit(1)

try:
    opts, args = getopt.getopt(sys.argv[1:],"i:r:t:",["image=", "repo=", "template="])
except getopt.GetoptError:
    usage()

image = ""
repo = ""
template = 'Dockerfile.jinja2'

for opt, arg in opts:
    if opt in ("-i", "--image"):
        image = arg
    if opt in ("-r", "--repo"):
        repo = arg
    if opt in ("-t", "--template"):
        template = arg
#
# Parse arguments
#
if (image == "" or repo == "") and len(args) < 1:
    usage()

p = {}

if image == "agent":
    p['base_docker_image'] = "debian:stable"
    p['sysdig_repository'] = repo
    p['include_agent_package'] = "apt"
    p['build_kernel_module'] = 1
    p['launch_dragent'] = 1
    p['thin'] = 0
elif image == "local":
    p['base_docker_image'] = "debian:stable"
    p['sysdig_repository'] = repo
    p['include_agent_package'] = "local"
    p['build_kernel_module'] = 1
    p['launch_dragent'] = 1
    p['thin'] = 0
elif image == "agent-kmodule":
    p['base_docker_image'] = "debian:stable"
    p['sysdig_repository'] = repo
    p['include_agent_package'] = "apt"
    p['build_kernel_module'] = 1
    p['launch_dragent'] = 0
    p['thin'] = 0
elif image == "agent-slim":
    p['base_docker_image'] = "adoptopenjdk/openjdk8:alpine-slim"
    p['sysdig_repository'] = repo
    p['build_kernel_module'] = 0
    p['launch_dragent'] = 1
    p['thin'] = 0
elif image == "agent-kmodule-thin":
    p['base_docker_image'] = "debian:stable"
    p['sysdig_repository'] = repo
    p['include_agent_package'] = "apt"
    p['build_kernel_module'] = 1
    p['launch_dragent'] = 0
    p['thin'] = 1

template_str = ""

with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), template),'r') as f:
    template_str = f.read()

template = jinja2.Template(template_str, trim_blocks=True)
dockerfile = template.render(p=p)
sys.stdout.write(dockerfile)


