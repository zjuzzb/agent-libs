module coldstart_manager

go 1.16

require (
	github.com/cihub/seelog v0.0.0-20170130134532-f561c5e57575
	github.com/draios/install_prefix v0.0.0-00010101000000-000000000000 // indirect
	github.com/draios/protorepo/sdc_internal v0.0.0-00010101000000-000000000000
	github.com/gogo/protobuf v1.3.2
	github.com/google/uuid v1.1.2
	github.com/wojas/genericr v0.2.0
	google.golang.org/grpc v1.27.1
	k8s.io/api v0.21.0
	k8s.io/apimachinery v0.21.0
	k8s.io/client-go v0.21.0
	k8s.io/klog/v2 v2.8.0
	protorepo/agent-be/proto v0.0.0-00010101000000-000000000000 // indirect
)

replace (
	github.com/draios/install_prefix => ../install_prefix
	github.com/draios/protorepo/sdc_internal => ../../../../build/generated-go/sdc_internal
	protorepo/agent-be/proto => ../../../../build/generated-go/draiosproto/protorepo/agent-be/proto
)
