module compclient

go 1.12

require (
	github.com/cihub/seelog v0.0.0-20151216151435-d2c6e5aa9fbf
	github.com/draios/protorepo/draiosproto v0.0.0-00010101000000-000000000000
	github.com/draios/install_prefix v0.0.0-00010101000000-000000000000
	github.com/draios/protorepo/sdc_internal v0.0.0-00010101000000-000000000000
	github.com/gogo/protobuf v0.0.0-20170307180453-100ba4e88506
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b // indirect
	github.com/golang/protobuf v1.1.0 // indirect
	golang.org/x/net v0.0.0-20180621144259-afe8f62b1d6b
	golang.org/x/sync v0.0.0-20190423024810-112230192c58 // indirect
	golang.org/x/text v0.3.0 // indirect
	google.golang.org/genproto v0.0.0-20180621235812-80063a038e33 // indirect
	google.golang.org/grpc v1.13.0
)

replace github.com/draios/protorepo/draiosproto => ../draiosproto

replace github.com/draios/protorepo/sdc_internal => ../sdc_internal

replace github.com/draios/install_prefix => ../install_prefix
