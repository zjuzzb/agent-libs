module cointerface

go 1.12

require (
	github.com/Azure/go-ansiterm v0.0.0-20170929234023-d6e3b3328b78 // indirect
	github.com/Microsoft/go-winio v0.4.11 // indirect
	github.com/StackExchange/wmi v0.0.0-20180116203802-5d049714c4a6 // indirect
	github.com/cihub/seelog v0.0.0-20151216151435-d2c6e5aa9fbf
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v1.14.0-0.20190319215453-e7b5f7dbe98c
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.3.3 // indirect
	github.com/draios/install_prefix v0.0.0-00010101000000-000000000000
	github.com/draios/protorepo/draiosproto v0.0.0-00010101000000-000000000000
	github.com/draios/protorepo/sdc_internal v0.0.0-00010101000000-000000000000
	github.com/draios/test_helpers v0.0.0
	github.com/evanphx/json-patch v4.2.0+incompatible // indirect
	github.com/go-ole/go-ole v1.2.2 // indirect
	github.com/gogo/protobuf v1.2.0
	github.com/golang/groupcache v0.0.0-20190702054246-869f871628b6 // indirect
	github.com/google/btree v1.0.0 // indirect
	github.com/google/go-cmp v0.3.1 // indirect
	github.com/google/gofuzz v0.0.0-20170612174753-24818f796faf // indirect
	github.com/googleapis/gnostic v0.2.0 // indirect
	github.com/gorilla/mux v1.7.3 // indirect
	github.com/gregjones/httpcache v0.0.0-20181110185634-c63ab54fda8f // indirect
	github.com/hashicorp/golang-lru v0.5.0 // indirect
	github.com/imdario/mergo v0.3.6 // indirect
	github.com/json-iterator/go v1.1.5 // indirect
	github.com/modern-go/reflect2 v0.0.0-20180701023420-4b7aa43c6742 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/opencontainers/go-digest v1.0.0-rc1 // indirect
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/peterbourgon/diskv v2.0.1+incompatible // indirect
	github.com/pkg/errors v0.8.1 // indirect
	github.com/shirou/gopsutil v2.18.12+incompatible
	github.com/shirou/w32 v0.0.0-20160930032740-bb4de0191aa4 // indirect
	github.com/sirupsen/logrus v1.4.2 // indirect
	github.com/spf13/pflag v1.0.3 // indirect
	golang.org/x/crypto v0.0.0-20190123085648-057139ce5d2b // indirect
	golang.org/x/net v0.0.0-20190108225652-1e06a53dbb7e
	golang.org/x/oauth2 v0.0.0-20190115181402-5dab4167f31c // indirect
	golang.org/x/time v0.0.0-20181108054448-85acf8d2951c // indirect
	google.golang.org/genproto v0.0.0-20190123001331-8819c946db44 // indirect
	google.golang.org/grpc v1.17.0
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v2 v2.2.2 // indirect
	gotest.tools v2.2.0+incompatible // indirect
	k8s.io/api v0.0.0-20181121191454-a61488babbd6
	k8s.io/apimachinery v0.0.0-20190117220443-572dfc7bdfcb
	k8s.io/client-go v0.0.0-20190115175254-86dbf26d38ed
	k8s.io/klog v0.1.0 // indirect
	k8s.io/kube-openapi v0.0.0-20190502190224-411b2483e503 // indirect
	sigs.k8s.io/yaml v1.1.0 // indirect
)

replace github.com/docker/docker v1.14.0-0.20190319215453-e7b5f7dbe98c => github.com/docker/docker v0.7.3-0.20190319215453-e7b5f7dbe98c

replace github.com/draios/install_prefix => ../install_prefix

replace github.com/draios/test_helpers => ../test_helpers

// The generated-go path comes from GEN_GO_DIR in userspace/cointerface/CMakeLists.txt
replace github.com/draios/protorepo/sdc_internal => ../../../../build/generated-go/sdc_internal

replace github.com/draios/protorepo/draiosproto => ../../../../build/generated-go/draiosproto
