module compclient

go 1.12

require (
	github.com/cihub/seelog v0.0.0-20151216151435-d2c6e5aa9fbf
	github.com/draios/install_prefix v0.0.0-00010101000000-000000000000
	github.com/draios/protorepo/sdc_internal v0.0.0-00010101000000-000000000000
	github.com/gogo/protobuf v1.3.1
	github.com/golang/protobuf v1.3.2
	golang.org/x/net v0.0.0-20190311183353-d8887717615a
	google.golang.org/grpc v1.24.0
	protorepo/agent-be/proto v0.0.0-00010101000000-000000000000
)

// The generated-go path comes from GEN_GO_DIR in userspace/cointerface/CMakeLists.txt
replace protorepo/agent-be/proto => ../../../../build/generated-go/draiosproto/protorepo/agent-be/proto

replace github.com/draios/protorepo/sdc_internal => ../../../../build/generated-go/sdc_internal

replace github.com/draios/install_prefix => ../install_prefix
