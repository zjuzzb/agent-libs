package heartbeat

import (
	"os"
	"time"
	"syscall"
	"fmt"
	"runtime"
)

func printHeartbeatMessage() {
	var rusage syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &rusage)
	if runtime.GOOS == "darwin" {
		// macOS reports max RSS in bytes
		rusage.Maxrss = rusage.Maxrss / 1024
	}
	fmt.Printf("HB,%d,%d,%d\n", os.Getpid(), rusage.Maxrss, time.Now().Unix())
}

func Heartbeat(preCall func()()) {
	for {
		if preCall != nil {
			preCall()
		}
		printHeartbeatMessage()
		time.Sleep(time.Second)
	}
}
