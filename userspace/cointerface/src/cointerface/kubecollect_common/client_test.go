package kubecollect_common

import (
	"testing"
	"time"
)

func TestMapInsert(t *testing.T) {
	var m map[string]string

	MapInsert(&m, "good", "bye")

	if m["good"] != "bye" {
		t.Fail()
	}
}

func TestShouldStart (t *testing.T) {

	var result bool

	result = shouldStartWatcherRetry(true, time.Hour*3) 

	if !result {
		t.Fail()
	}

	result = shouldStartWatcherRetry(true, time.Minute*3) 

	if !result {
		t.Fail()
	}

	result = shouldStartWatcherRetry(false, time.Hour*3) 

	if !result {
		t.Fail()
	}

	result = shouldStartWatcherRetry(false, time.Minute*3) 

	if result {
		t.Fail()
	}
}

func TestUptime (t *testing.T) {

	uptimeInit()

	time.Sleep(2 * time.Second)

	uptimeDuration := uptime()

	result := uptimeDuration > time.Second*1 && uptimeDuration < time.Minute*1

	if !result {
		t.Fail()
	}
}
