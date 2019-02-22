#!/bin/bash
export PATH=/bin:/cygdrive/c/cygwin64/bin:$PATH
export LD_LIBRARY_PATH=/bin:/cygdrive/c/cygwin64/bin
cd /code/agent
./bootstrap-agent
cd /code/agent/build/release/userspace/dragent
make install
cd /opt/draios
./make_msi.sh