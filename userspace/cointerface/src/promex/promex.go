package main

import (
	"flag"
	"log"
	"net"

	"os"
	"os/signal"
	"syscall"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"net/http"

	pb "promex/promex_pb"
	"promex/server"
	"strings"
	"install_prefix"
	"heartbeat"
)

func main() {
	prefix, err := install_prefix.GetInstallPrefix()
	if err != nil {
		log.Printf("Error: Could not determine installation directory: %s", err)
		os.Exit(1)
	}
	pbProto := flag.String("pb-proto", "unix", "Agent listen protocol (tcp, unix)")
	pbAddr := flag.String("pb-addr", prefix + "/run/promex.sock", "Agent listen address (ip:port or Unix socket path)")
	promAddr := flag.String("prom-addr", "127.0.0.1:9544", "Prometheus listen address (ip:port)")
	containerLabels := flag.String("container-labels", "", "Container labels to export (comma-separated)")
	metricTimeout := flag.Int("pb-timeout", 60, "Timeout in seconds before declaring the agent down")

	flag.Parse()

	if *pbProto == "unix" {
		os.Remove(*pbAddr)
	}

	lis, err := net.Listen(*pbProto, *pbAddr)
	if err != nil {
		log.Fatalf("Error: failed to listen on %s (%s socket): %v", *pbAddr, *pbProto, err)
	}

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, os.Kill, syscall.SIGTERM)
	go func(c chan os.Signal) {
		// Wait for a SIGINT or SIGKILL:
		sig := <-c
		log.Printf("Info: Caught signal %s: shutting down.", sig)
		// Stop listening (and unlink the socket if unix type):
		lis.Close()
		// And we're done:
		os.Exit(0)
	}(sigc)

	grpcServer := grpc.NewServer()
	exporter := server.NewServer(
		strings.Split(*containerLabels, ","),
		*metricTimeout,
	)
	pb.RegisterPrometheusExporterServer(grpcServer, exporter)

	go func() {
		http.Handle("/metrics", promhttp.Handler())
		// The following message was provided to Goldman Sachs (Oct 2018). Do not change.
		log.Printf("Info: Serving Prometheus stats on %s", *promAddr)
		log.Fatal(http.ListenAndServe(*promAddr, nil))
	}()

	go heartbeat.Heartbeat(func() {
		exporter.CheckLock()
	})

	log.Printf("Info: Listening on %s socket %s", *pbProto, *pbAddr)
	log.Fatal(grpcServer.Serve(lis))
}
