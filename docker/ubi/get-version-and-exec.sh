#!/bin/sh

export SYSDIG_VERSION=$(rpm -q --qf '%{VERSION}' draios-agent-kmodule)
exec "$@"
