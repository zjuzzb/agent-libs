module promex

go 1.12

require (
	github.com/beorn7/perks v0.0.0-20180321164747-3a771d992973 // indirect
	github.com/draios/heartbeat v0.0.0-00010101000000-000000000000
	github.com/draios/install_prefix v0.0.0-00010101000000-000000000000
	github.com/draios/protorepo/draiosproto v0.0.0-00010101000000-000000000000
	github.com/draios/protorepo/promex_pb v0.0.0-00010101000000-000000000000
	github.com/golang/protobuf v1.3.2
	github.com/matttproud/golang_protobuf_extensions v1.0.1 // indirect
	github.com/prometheus/client_golang v0.8.0
	github.com/prometheus/client_model v0.0.0-20180712105110-5c3871d89910 // indirect
	github.com/prometheus/common v0.0.0-20180518154759-7600349dcfe1 // indirect
	github.com/prometheus/procfs v0.0.0-20180705121852-ae68e2d4c00f // indirect
	golang.org/x/net v0.0.0-20190311183353-d8887717615a
	google.golang.org/grpc v1.23.1
)

replace github.com/draios/protorepo/draiosproto => ../draiosproto

replace github.com/draios/protorepo/promex_pb => ../promex_pb

replace github.com/draios/heartbeat => ../heartbeat

replace github.com/draios/install_prefix => ../install_prefix
