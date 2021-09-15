module sysdig.com/coclient

go 1.15

require (
	github.com/cihub/seelog v0.0.0-20170130134532-f561c5e57575
	github.com/draios/install_prefix v0.0.0-00010101000000-000000000000
	github.com/draios/protorepo/sdc_internal v0.0.0-00010101000000-000000000000
	github.com/gogo/protobuf v1.3.2
	golang.org/x/net v0.0.0-20210520170846-37e1c6afe023
	google.golang.org/grpc v1.27.1
	k8s.io/client-go v0.20.10
)

require protorepo/agent-be/proto v0.0.0-00010101000000-000000000000 // indirect

// The generated-go path comes from GEN_GO_DIR in userspace/cointerface/CMakeLists.txt
replace github.com/draios/protorepo/sdc_internal => ../../../../build/generated-go/sdc_internal

replace github.com/draios/install_prefix => ../install_prefix

replace protorepo/agent-be/proto => ../../../../build/generated-go/draiosproto/protorepo/agent-be/proto
