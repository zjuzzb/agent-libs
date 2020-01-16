module cointerface

go 1.12

require (
	github.com/Azure/go-ansiterm v0.0.0-20170929234023-d6e3b3328b78 // indirect
	github.com/Microsoft/go-winio v0.4.11 // indirect
	github.com/StackExchange/wmi v0.0.0-20180116203802-5d049714c4a6 // indirect
	github.com/cihub/seelog v0.0.0-20151216151435-d2c6e5aa9fbf
	github.com/containerd/cgroups v0.0.0-20191118204028-bd09c0d4a789
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v1.14.0-0.20190319215453-e7b5f7dbe98c
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/draios/install_prefix v0.0.0-00010101000000-000000000000
	github.com/draios/protorepo/draiosproto v0.0.0-00010101000000-000000000000
	github.com/draios/protorepo/sdc_internal v0.0.0-00010101000000-000000000000
	github.com/draios/test_helpers v0.0.0
	github.com/go-ole/go-ole v1.2.2 // indirect
	github.com/gogo/protobuf v1.3.1
	github.com/golang/protobuf v1.3.2
	github.com/google/go-cmp v0.3.1 // indirect
	github.com/googleapis/gnostic v0.2.0 // indirect
	github.com/gorilla/mux v1.7.3 // indirect
	github.com/imdario/mergo v0.3.6 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/opencontainers/go-digest v1.0.0-rc1 // indirect
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/shirou/gopsutil v2.18.12+incompatible
	google.golang.org/grpc v1.24.0
	golang.org/x/net v0.0.0-20190812203447-cdfb69ac37fc
	k8s.io/api v0.0.0-20191003000013-35e20aa79eb8
	k8s.io/apimachinery v0.0.0-20190913080033-27d36303b655
	k8s.io/client-go v0.0.0-20191003000419-f68efa97b39e
	github.com/pkg/errors v0.8.1
	golang.org/x/net v0.0.0-20191004110552-13f9640d40b9
	k8s.io/cri-api v0.0.0-20191107035106-03d130a7dc28
)

replace github.com/docker/docker v1.14.0-0.20190319215453-e7b5f7dbe98c => github.com/docker/docker v0.7.3-0.20190319215453-e7b5f7dbe98c

replace github.com/draios/install_prefix => ../install_prefix

replace github.com/draios/test_helpers => ../test_helpers

// The generated-go path comes from GEN_GO_DIR in userspace/cointerface/CMakeLists.txt
replace github.com/draios/protorepo/sdc_internal => ../../../../build/generated-go/sdc_internal

replace github.com/draios/protorepo/draiosproto => ../../../../build/generated-go/draiosproto
