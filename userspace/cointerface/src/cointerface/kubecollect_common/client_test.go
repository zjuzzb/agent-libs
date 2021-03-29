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

func TestGetBackoffValue_invalidPreviousBackoff(t *testing.T) {

	value := getBackoffValue(3*time.Second, 0*time.Second)
	expected := WATCHER_MINIMUM_BACKOFF

	if value != expected {
		t.Errorf("%s != %s", value.String(), expected.String())
		t.Fail()
	}
}

func TestGetBackoffValue_normalComplete(t *testing.T) {

	value := getBackoffValue(3*time.Second, 0*time.Second)
	// Don't use contants for this test; manually check values
	expected := 1 * time.Minute

	if value != expected {
		t.Errorf("%s != %s", value.String(), expected.String())
		t.Fail()
	}

	value = getBackoffValue(3*time.Second, expected)
	expected = 2 * time.Minute

	if value != expected {
		t.Errorf("%s != %s", value.String(), expected.String())
		t.Fail()
	}

	value = getBackoffValue(3*time.Second, expected)
	expected = 4 * time.Minute

	if value != expected {
		t.Errorf("%s != %s", value.String(), expected.String())
		t.Fail()
	}

	value = getBackoffValue(3*time.Second, expected)
	expected = 8 * time.Minute

	if value != expected {
		t.Errorf("%s != %s", value.String(), expected.String())
		t.Fail()
	}

	value = getBackoffValue(3*time.Second, expected)
	expected = 16 * time.Minute

	if value != expected {
		t.Errorf("%s != %s", value.String(), expected.String())
		t.Fail()
	}

	value = getBackoffValue(3*time.Second, expected)
	expected = 32 * time.Minute

	if value != expected {
		t.Errorf("%s != %s", value.String(), expected.String())
		t.Fail()
	}

	value = getBackoffValue(3*time.Second, expected)
	expected = 1 * time.Hour

	if value != expected {
		t.Errorf("%s != %s", value.String(), expected.String())
		t.Fail()
	}

	value = getBackoffValue(3*time.Second, expected)
	expected = 1 * time.Hour

	if value != expected {
		t.Errorf("%s != %s", value.String(), expected.String())
		t.Fail()
	}

	value = getBackoffValue(3*time.Second, expected)
	expected = 1 * time.Hour

	if value != expected {
		t.Errorf("%s != %s", value.String(), expected.String())
		t.Fail()
	}

	value = getBackoffValue(3*time.Second, expected)
	expected = 1 * time.Hour

	if value != expected {
		t.Errorf("%s != %s", value.String(), expected.String())
		t.Fail()
	}
}

func TestGetBackoffValue_normalRecover(t *testing.T) {

	value := getBackoffValue(3*time.Second, 0*time.Second)
	// Don't use contants for this test; manually check values
	expected := 1 * time.Minute

	if value != expected {
		t.Errorf("%s != %s", value.String(), expected.String())
		t.Fail()
	}

	value = getBackoffValue(3*time.Second, expected)
	expected = 2 * time.Minute

	if value != expected {
		t.Errorf("%s != %s", value.String(), expected.String())
		t.Fail()
	}

	value = getBackoffValue(3*time.Second, expected)
	expected = 4 * time.Minute

	if value != expected {
		t.Errorf("%s != %s", value.String(), expected.String())
		t.Fail()
	}

	value = getBackoffValue(1*time.Hour + time.Second, expected)
	expected = 1 * time.Minute

	if value != expected {
		t.Errorf("%s != %s", value.String(), expected.String())
		t.Fail()
	}
}

func TestGetBackoffValue_maxBackoff(t *testing.T) {

	value := getBackoffValue(3*time.Second, WATCHER_MAXIMUM_BACKOFF - time.Second)
	expected := WATCHER_MAXIMUM_BACKOFF

	if value != expected {
		t.Errorf("%s != %s", value.String(), expected.String())
		t.Fail()
	}

	value = getBackoffValue(3*time.Second, WATCHER_MAXIMUM_BACKOFF)
	if value != expected {
		t.Errorf("%s != %s", value.String(), expected.String())
		t.Fail()
	}

	value = getBackoffValue(3*time.Second, WATCHER_MAXIMUM_BACKOFF + time.Second)
	if value != expected {
		t.Errorf("%s != %s", value.String(), expected.String())
		t.Fail()
	}
}

func TestGetBackoffValue_longRuntime(t *testing.T) {

	value := getBackoffValue(3*time.Hour, 1*time.Hour)
	expected := WATCHER_MINIMUM_BACKOFF

	if value != expected {
		t.Errorf("%s != %s", value.String(), expected.String())
		t.Fail()
	}
}

func TestGetBackoffValue_random(t *testing.T) {

	value := getBackoff(3*time.Hour, 1*time.Hour)
	min := WATCHER_MINIMUM_BACKOFF
	max := min + min/2

	if value < min || value > max {
		t.Errorf("%s < %s || %s > %s", value.String(), min.String(), value.String(), max.String())
		t.Fail()
	}

	value = getBackoff(3*time.Second, 2 * time.Minute)
	min = 4 * time.Minute
	max = min + min/2

	if value < min || value > max {
		t.Errorf("%s < %s || %s > %s", value.String(), min.String(), value.String(), max.String())
		t.Fail()
	}

	value = getBackoff(3*time.Second, WATCHER_MAXIMUM_BACKOFF)
	min = WATCHER_MAXIMUM_BACKOFF
	max = min + min/2

	if value < min || value > max {
		t.Errorf("%s < %s || %s > %s", value.String(), min.String(), value.String(), max.String())
		t.Fail()
	}
}

