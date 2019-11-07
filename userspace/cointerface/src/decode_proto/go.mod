module decode_proto

go 1.12

require (
	github.com/draios/protorepo/draiosproto v0.0.0-00010101000000-000000000000
	github.com/gogo/protobuf v1.2.0
	github.com/golang/protobuf v1.2.0 // indirect
)

// The generated-go path comes from GEN_GO_DIR in userspace/cointerface/CMakeLists.txt
replace github.com/draios/protorepo/draiosproto => ../../../../build/generated-go/draiosproto
