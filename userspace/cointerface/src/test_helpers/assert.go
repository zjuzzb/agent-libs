package test_helpers

import (
	"fmt"
	"reflect"
	"runtime"
	"testing"
)

// Go up a level in the stack frame so that we print the write file/line
func up(frame int, s string) string {
    _, origFile, origLine, _ := runtime.Caller(1)
    _, frameFile, frameLine, _ := runtime.Caller(frame + 1)
    if origFile != frameFile {
        return s // Deferred call after a panic or runtime.Goexit()
    }
    erase := []byte("\b\b\b")
    for ; origLine > 9; origLine /= 10 {
        erase = append(erase, '\b')
    }
    return fmt.Sprintf("%s%d: %s", erase, frameLine, s)
}

// AssertEqual checks if values are equal
func AssertEqual(t *testing.T, expected interface{}, actual interface{}) {
	if actual == expected {
		return
	}
	error := fmt.Sprintf("ASSERTION FAILED\nReceived [%v]: %v \nExpected [%v]: %v ", reflect.TypeOf(actual), actual, reflect.TypeOf(expected), expected)
	t.Errorf(up(1, error))
	t.Fail()
}
