#!/bin/bash
g++ -std=c++11 -O3 -fno-strict-aliasing -DNDEBUG -o metric_limits main.cpp -I./ -I../../userspace/libsanalyzer -I../../../sysdig/userspace/libsinsp -L../../../sysdig/build/release/userspace/libsinsp -lsinsp
