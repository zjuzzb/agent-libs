module promex

go 1.12

require (
	github.com/beorn7/perks v0.0.0-20180321164747-3a771d992973 // indirect
	github.com/draios/protorepo/draiosproto v0.0.0-00010101000000-000000000000
	github.com/draios/heartbeat v0.0.0-00010101000000-000000000000
	github.com/draios/install_prefix v0.0.0-00010101000000-000000000000
	github.com/draios/protorepo/promex_pb v0.0.0-00010101000000-000000000000
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b // indirect
	github.com/golang/protobuf v1.1.0 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.1 // indirect
	github.com/prometheus/client_golang v0.8.0
	github.com/prometheus/client_model v0.0.0-20180712105110-5c3871d89910 // indirect
	github.com/prometheus/common v0.0.0-20180518154759-7600349dcfe1 // indirect
	github.com/prometheus/procfs v0.0.0-20180705121852-ae68e2d4c00f // indirect
	golang.org/x/net v0.0.0-20180712202826-d0887baf81f4
	golang.org/x/sync v0.0.0-20190423024810-112230192c58 // indirect
	golang.org/x/text v0.3.0 // indirect
	google.golang.org/genproto v0.0.0-20180716172848-2731d4fa720b // indirect
	google.golang.org/grpc v1.13.0
)

replace github.com/draios/protorepo/draiosproto => ../draiosproto

replace github.com/draios/protorepo/promex_pb => ../promex_pb

replace github.com/draios/heartbeat => ../heartbeat

replace github.com/draios/install_prefix => ../install_prefix
