package leader_lib

import (
	"github.com/draios/protorepo/sdc_internal"
	"github.com/gogo/protobuf/proto"
	"io/ioutil"
	"os"
	"testing"
)

func TestGetLeaseNamespace(t *testing.T) {
	conf := sdc_internal.LeaderElectionConf{
		LeaseDuration:        nil,
		RenewDeadline:        nil,
		RetryPeriod:          nil,
		Namespace:            proto.String("marIonio"),
	}

	lpm := LeasePoolManager{}
	var nsPath = "/tmp/ns"
	defer os.Remove(nsPath)
	lpm.setLeaseNamespace(&conf, &nsPath)

	if *conf.Namespace != "marIonio" {
		t.Fail()
	}

	*conf.Namespace = ""

	lpm.setLeaseNamespace(&conf, &nsPath)

	if *conf.Namespace != "sysdig-agent" {
		t.Fail()
	}

	*conf.Namespace = ""

	ioutil.WriteFile(nsPath, []byte("marTirreno"), 0644)

	lpm.setLeaseNamespace(&conf, &nsPath)

	if *conf.Namespace != "marTirreno" {
		t.Fail()
	}
}

