package main

import (
    "fmt"
    "net/http"
    "syscall"
)

func handler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Hello world!")
}

func main() {
	var v syscall.Rlimit
	v.Cur = 1000000
	v.Max = 1000000
	syscall.Setrlimit(syscall.RLIMIT_NOFILE,&v)
    http.HandleFunc("/", handler)
    http.ListenAndServe(":8080", nil)
}