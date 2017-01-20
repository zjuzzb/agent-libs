#Introduction

This directory contails a utility program that can diff the output of
two files created by sinsp-open. It depends on google protobuf >=
3.1.0. Note that this is a different version than the version used by
the agent itself.

# Usage

```
diff_pb first-pb-file second-pb-file
```

# Return Value

If the two protobuf files are equal, returns 0. Otherwise, prints a description of differences and returns 1.

# Sample Output

```
$ ./diff_pb m1.dams m2.dams
Differ. Differences:
modified: metrics[0].hostinfo.system_load_1: 32 -> 16
modified: metrics[0].hostinfo.system_load_5: 8 -> 5
modified: metrics[0].hostinfo.system_load_15: 7 -> 6
modified: metrics[1].hostinfo.tcounters.io_file.time_ns_other: 38856966 -> 38855617
modified: metrics[1].hostinfo.tcounters.io_file.count_other: 5752 -> 5751
modified: metrics[1].hostinfo.resource_counters.minor_pagefaults: 9499 -> 9286
modified: metrics[1].hostinfo.system_load_1: 32 -> 16
modified: metrics[1].hostinfo.system_load_5: 8 -> 5
modified: metrics[1].hostinfo.system_load_15: 7 -> 6
modified: metrics[1].programs[106].procinfo.tcounters.other.time_percentage: 8790 -> 8872
modified: metrics[1].programs[106].procinfo.tcounters.io_file.time_ns_other: 16481 -> 15132
modified: metrics[1].programs[106].procinfo.tcounters.io_file.count_other: 10 -> 9
modified: metrics[1].programs[106].procinfo.tcounters.io_file.time_percentage_other: 1134 -> 1051
modified: metrics[1].programs[106].procinfo.resource_counters.minor_pagefaults: 213 -> 0
modified: metrics[1].containers[7].tcounters.io_file.time_ns_other: 320493 -> 319144
modified: metrics[1].containers[7].tcounters.io_file.count_other: 197 -> 196
modified: metrics[1].containers[7].resource_counters.minor_pagefaults: 1414 -> 1201
modified: metrics[2].hostinfo.system_load_1: 32 -> 16
modified: metrics[2].hostinfo.system_load_5: 8 -> 5
modified: metrics[2].hostinfo.system_load_15: 7 -> 6
modified: metrics[3].hostinfo.system_load_1: 32 -> 16
modified: metrics[3].hostinfo.system_load_5: 8 -> 5
modified: metrics[3].hostinfo.system_load_15: 7 -> 6
modified: metrics[4].hostinfo.system_load_1: 32 -> 16
modified: metrics[4].hostinfo.system_load_5: 8 -> 5
modified: metrics[4].hostinfo.system_load_15: 7 -> 6
modified: metrics[5].hostinfo.system_load_1: 32 -> 16
modified: metrics[5].hostinfo.system_load_5: 8 -> 5
modified: metrics[5].hostinfo.system_load_15: 7 -> 6
```


