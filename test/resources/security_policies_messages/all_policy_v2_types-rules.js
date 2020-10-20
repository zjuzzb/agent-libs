[
    {"id": 1000,
     "name": "read sample-sensitive-file-1.txt",
     "origin": "secure UI",
     "versionId": 1,
     "filename": "fastengine_rules.yaml",
     "tags": [],
     "description": "",
     "details": {
	 "ruleType": "FILESYSTEM",
	 "readPaths": {
	     "items": ["/tmp/sample-sensitive-file-1.txt"],
	     "matchItems": true
	 }
     }
    },
    {"id": 1001,
     "name": "write sample-sensitive-file-3.txt",
     "origin": "secure UI",
     "versionId": 1,
     "filename": "fastengine_rules.yaml",
     "tags": [],
     "description": "",
     "details": {
	 "ruleType": "FILESYSTEM",
	 "readWritePaths": {
	     "items": ["/tmp/sample-sensitive-file-3.txt"],
	     "matchItems": true
	 }
     }
    },
    {"id": 1002,
     "name": "listen tcp port 1234",
     "origin": "secure UI",
     "versionId": 1,
     "filename": "fastengine_rules.yaml",
     "tags": [],
     "description": "",
     "details": {
	 "ruleType": "NETWORK",
	 "allInbound": false,
	 "allOutbound": false,
	 "tcpListenPorts": {
	     "items": ["1234"],
	     "matchItems": true
	 }
     }
    },
    {"id": 1003,
     "name": "listen udp port 12345",
     "origin": "secure UI",
     "versionId": 1,
     "filename": "fastengine_rules.yaml",
     "tags": [],
     "description": "",
     "details": {
	 "ruleType": "NETWORK",
	 "allInbound": false,
	 "allOutbound": false,
	 "udpListenPorts": {
	     "items": ["12345"],
	     "matchItems": true
	 }
     }
    },
    {"id": 1004,
     "name": "match quotactl",
     "origin": "secure UI",
     "versionId": "0.1.1",
     "filename": "fastengine_rules.yaml",
     "tags": [],
     "description": "",
     "details": {
	 "ruleType": "SYSCALL",
	 "syscalls": {
	     "items": ["quotactl"],
	     "matchItems": true
	 }
     }
    },
    {"id": 1999,
     "name": "busybox syscall-whitelist",
     "origin": "secure UI",
     "versionId": "0.1.1",
     "filename": "fastengine_rules.yaml",
     "tags": [],
     "description": "",
     "details": {
       "ruleType": "SYSCALL",
       "syscalls": {
           "items": ["arch_prctl",
		     "brk",
		     "clone",
		     "container",
		     "execve",
		     "exit_group",
		     "getuid",
		     "ioctl",
		     "nanosleep",
		     "open",
		     "rt_sigaction",
		     "signaldeliver",
		     "sigreturn",
		     "switch",
		     "utimes",
		     "wait4"],
         "matchItems": false
        }
      }
    },
    {"id": 1005,
     "name": "match blacklist-image-name container",
     "origin": "secure UI",
     "versionId": "0.1.1",
     "filename": "fastengine_rules.yaml",
     "tags": [],
     "description": "",
     "details": {
	 "ruleType": "CONTAINER",
	 "containers": {
	     "items": ["blacklist-image-name"],
	     "matchItems": true
	 }
     }
    },
    {"id": 1006,
     "name": "match process ls",
     "origin": "secure UI",
     "versionId": "0.1.1",
     "filename": "fastengine_rules.yaml",
     "tags": [],
     "description": "",
     "details": {
	 "ruleType": "PROCESS",
	 "processes": {
	     "items": ["ls"],
	     "matchItems": true
	 }
     }
    },
    {"id": 1007,
     "name": "match /tmp/{one,two}",
     "origin": "secure UI",
     "versionId": "0.1.1",
     "filename": "fastengine_rules.yaml",
     "tags": [],
     "description": "",
     "details": {
	 "ruleType": "FILESYSTEM",
	 "readPaths": {
	     "items": ["/tmp/one","/tmp/two"],
	     "matchItems": true
	 }
     }
    },
    {"id": 1008,
     "name": "match my.domain.name/",
     "origin": "secure UI",
     "versionId": "0.1.1",
     "filename": "fastengine_rules.yaml",
     "tags": [],
     "description": "",
     "details": {
	 "ruleType": "CONTAINER",
	 "containers": {
	     "items": ["my.domain.name/"],
	     "matchItems": true
	 }
     }
    },
    {"id": 1009,
     "name": "match my.other.domain.name:12345/",
     "origin": "secure UI",
     "versionId": "0.1.1",
     "filename": "fastengine_rules.yaml",
     "tags": [],
     "description": "",
     "details": {
	 "ruleType": "CONTAINER",
	 "containers": {
	     "items": ["my.other.domain.name:12345/"],
	     "matchItems": true
	 }
     }
    },
    {"id": 1010,
     "name": "match my.third.domain.name/cirros",
     "origin": "secure UI",
     "versionId": "0.1.1",
     "filename": "fastengine_rules.yaml",
     "tags": [],
     "description": "",
     "details": {
	 "ruleType": "CONTAINER",
	 "containers": {
	     "items": ["my.third.domain.name/cirros"],
	     "matchItems": true
	 }
     }
    },
    {"id": 1011,
     "name": "match my.third.domain.name/tutum/curl:alpine",
     "origin": "secure UI",
     "versionId": "0.1.1",
     "filename": "fastengine_rules.yaml",
     "tags": [],
     "description": "",
     "details": {
	 "ruleType": "CONTAINER",
	 "containers": {
	     "items": ["my.third.domain.name/tutum/curl:alpine"],
	     "matchItems": true
	 }
     }
    },
    {"id": 1012,
     "name": "match inbound + outbound + tcp 22222",
     "origin": "secure UI",
     "versionId": "0.1.1",
     "filename": "fastengine_rules.yaml",
     "tags": [],
     "description": "",
     "details": {
	 "ruleType": "NETWORK",
	 "allInbound": true,
	 "allOutbound": true,
	 "tcpListenPorts": {
	     "items": ["22222"],
	     "matchItems": true
	 }
     }
    },
    {"id": 1013,
     "name": "match anything other than allowed/dev/proc paths",
     "origin": "secure UI",
     "versionId": "0.1.1",
     "filename": "fastengine_rules.yaml",
     "tags": [],
     "description": "",
     "details": {
	 "ruleType": "FILESYSTEM",
	 "readWritePaths": {
	     "items": ["/allowed-file-below-root", "/dev/null", "/proc/1/attr/exec"],
	     "matchItems": false
	 }
     }
    },
    {"id": 1014,
     "name": "match mnt etc for writes",
     "origin": "secure UI",
     "versionId": "0.1.1",
     "filename": "fastengine_rules.yaml",
     "tags": [],
     "description": "",
     "details": {
	 "ruleType": "FILESYSTEM",
	 "readWritePaths": {
	     "items": ["/mnt", "/etc"],
	     "matchItems": true
	 }
     }
    },
    {"id": 1015,
     "name": "match etc/passwd for reads",
     "origin": "secure UI",
     "versionId": "0.1.1",
     "filename": "fastengine_rules.yaml",
     "tags": [],
     "description": "",
     "details": {
	 "ruleType": "FILESYSTEM",
	 "readPaths": {
	     "items": ["/etc/passwd"],
	     "matchItems": true
	 }
     }
    },
    {"id": 1016,
     "name": "match bin for writes",
     "origin": "secure UI",
     "versionId": "0.1.1",
     "filename": "fastengine_rules.yaml",
     "tags": [],
     "description": "",
     "details": {
	 "ruleType": "FILESYSTEM",
	 "readWritePaths": {
	     "items": ["/bin"],
	     "matchItems": true
	 }
     }
    },
    {"id": 1018,
     "name": "match test_no_fd_ops",
     "origin": "secure UI",
     "versionId": "0.1.1",
     "filename": "fastengine_rules.yaml",
     "tags": [],
     "description": "",
     "details": {
	 "ruleType": "FILESYSTEM",
	 "readWritePaths": {
	     "items": ["/tmp/test_nofd_ops/"],
	     "matchItems": true
	 }
     }
    },
    {"id": 1019,
     "name": "match anything other than alpine",
     "origin": "secure UI",
     "versionId": "0.1.1",
     "filename": "fastengine_rules.yaml",
     "tags": [],
     "description": "",
     "details": {
	 "ruleType": "CONTAINER",
	 "containers": {
	     "items": ["alpine"],
	     "matchItems": false
	 }
     }
    },
    {"id": 1020,
     "name": "match busybox:some-tag",
     "origin": "secure UI",
     "versionId": "0.1.1",
     "filename": "fastengine_rules.yaml",
     "tags": [],
     "description": "",
     "details": {
	 "ruleType": "CONTAINER",
	 "containers": {
	     "items": ["busybox:some-tag"],
	     "matchItems": true
	 }
     }
    },
    {"id": 1021,
     "name": "match /tmp/second",
     "origin": "secure UI",
     "versionId": "0.1.1",
     "filename": "fastengine_rules.yaml",
     "tags": [],
     "description": "",
     "details": {
	 "ruleType": "FILESYSTEM",
	 "readWritePaths": {
	     "items": ["/tmp/second"],
	     "matchItems": true
	 }
     }
    },
    {"id": 1022,
     "name": "match /tmp/third",
     "origin": "secure UI",
     "versionId": "0.1.1",
     "filename": "fastengine_rules.yaml",
     "tags": [],
     "description": "",
     "details": {
	 "ruleType": "FILESYSTEM",
	 "readWritePaths": {
	     "items": ["/tmp/third"],
	     "matchItems": true
	 }
     }
    },
    {"id": 1023,
    "name": "match process gzip",
    "origin": "secure UI",
    "versionId": "0.1.1",
    "filename": "fastengine_rules.yaml",
    "tags": [],
    "description": "",
    "details": {
    "ruleType": "PROCESS",
    "processes": {
        "items": ["gzip"],
        "matchItems": true
      }
     }
    },
    {"id": 1024,
    "name": "match process lzcat",
    "origin": "secure UI",
    "versionId": "0.1.1",
    "filename": "fastengine_rules.yaml",
    "tags": [],
    "description": "",
    "details": {
    "ruleType": "PROCESS",
    "processes": {
        "items": ["lzcat"],
        "matchItems": true
      }
     }
    },
    {"id": 1025,
    "name": "match process bzip2",
    "origin": "secure UI",
    "versionId": "0.1.1",
    "filename": "fastengine_rules.yaml",
    "tags": [],
    "description": "",
    "details": {
    "ruleType": "PROCESS",
    "processes": {
        "items": ["bzip2"],
        "matchItems": true
      }
     }
    },
    {"id": 1026,
    "name": "match process bunzip2",
    "origin": "secure UI",
    "versionId": "0.1.1",
    "filename": "fastengine_rules.yaml",
    "tags": [],
    "description": "",
    "details": {
    "ruleType": "PROCESS",
    "processes": {
        "items": ["bunzip2"],
        "matchItems": true
      }
     }
    },
    {"id": 1027,
    "name": "match process bzcat",
    "origin": "secure UI",
    "versionId": "0.1.1",
    "filename": "fastengine_rules.yaml",
    "tags": [],
    "description": "",
    "details": {
    "ruleType": "PROCESS",
    "processes": {
        "items": ["bzcat"],
        "matchItems": true
      }
     }
    },    
    {"id": 1028,
     "name": "read sample-sensitive-file-4.txt",
     "origin": "secure UI",
     "versionId": 1,
     "filename": "fastengine_rules.yaml",
     "tags": [],
     "description": "",
     "details": {
	 "ruleType": "FILESYSTEM",
	 "readPaths": {
	     "items": ["/tmp/sample-sensitive-file-4.txt"],
	     "matchItems": true
	 }
     }
    },
    {"id": 1029,
     "name": "read sample-sensitive-file-5.txt",
     "origin": "secure UI",
     "versionId": 1,
     "filename": "fastengine_rules.yaml",
     "tags": [],
     "description": "",
     "details": {
	 "ruleType": "FILESYSTEM",
	 "readWritePaths": {
	     "items": ["/tmp/sample-sensitive-file-5.txt"],
	     "matchItems": true
	 }
     }
    }
]
