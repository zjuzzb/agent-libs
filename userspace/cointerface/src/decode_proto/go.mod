module decode_proto

go 1.12

require (
	github.com/gogo/protobuf v1.3.1
	github.com/golang/protobuf v1.3.2
	protorepo/agent-be/proto v0.0.0-00010101000000-000000000000
)

// The generated-go path comes from GEN_GO_DIR in userspace/cointerface/CMakeLists.txt
replace protorepo/agent-be/proto => ../../../../build/generated-go/draiosproto/protorepo/agent-be/proto
