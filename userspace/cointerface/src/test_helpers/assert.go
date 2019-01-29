package test_helpers

import (
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

// Go up a level in the stack frame so that we print the write file/line
func up(t *testing.T, frame int, s string) string {
    _, frameFile, frameLine, _ := runtime.Caller(frame + 1)
	_, file := filepath.Split(frameFile)
    return fmt.Sprintf("%s:%d %s", file, frameLine, s)
}

// AssertEqual checks if values are equal
func AssertEqual(t *testing.T, expected interface{}, actual interface{}) {
	if actual == expected {
		return
	}
	error := fmt.Sprintf("ASSERTION FAILED\nReceived [%v]: %v \nExpected [%v]: %v ", reflect.TypeOf(actual), actual, reflect.TypeOf(expected), expected)
	t.Errorf("\n" + up(t, 1, error))
	t.Fail()
}
