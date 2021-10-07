package main

import (
	"context"
	"flag"
	"fmt"
	log "github.com/cihub/seelog"
	"github.com/draios/protorepo/sdc_internal"
	"github.com/gogo/protobuf/proto"
	"google.golang.org/grpc"
	"net/http"
	"strconv"
	"strings"
)

func setupLogger() (log.LoggerInterface, error) {
	config := ` 
<seelog>
	<formats>
	<format id="agent-plain" format="%Msg%n"/>
	</formats>
	<outputs>
	<console formatid="agent-plain"/>
	</outputs>
	</seelog>`
	logger, err := log.LoggerFromConfigAsString(config)
	return logger, err
}

func main() {

	logger, _ := setupLogger()
	defer logger.Flush()

	var sock = flag.String("socket", "/tmp/coldstart.sock", "gRPC server will listen on this port")
	var heltzPort = flag.Int("healthz-port", 8080, "readiness http port")
	var numLeases = flag.Int("num-leases", 4, "leases numbers")
	var leaseNamespace = flag.String("namespace", "sysdig-agent", "kubernetes namespace where leases will be created")
	var apiServerUrl = flag.String("api-server-url", "https://kubernetes.default.svc:443", "api server address")

	flag.Parse()

	var opts []grpc.DialOption
	opts = append(opts, grpc.EmptyDialOption{})
	conn, err := grpc.Dial(fmt.Sprintf("unix:%s", *sock), grpc.WithInsecure())

	if err != nil {
		log.Error("Error starting the client %s", err.Error())
	}

	var client sdc_internal.LeasePoolManagerClient

	client = sdc_internal.NewLeasePoolManagerClient(conn)
	ctx, _ := context.WithCancel(context.Background())

	_, err = client.Init(ctx, &sdc_internal.LeasePoolInit{
		Id:        proto.String(""),
		LeaseName: proto.String("coldstart"),
		LeaseNum:  proto.Uint32(uint32(*numLeases)),
		Cmd: &sdc_internal.OrchestratorEventsStreamCommand{
			Url:                       proto.String(*apiServerUrl),
			CaCert:                    proto.String(""),
			ClientCert:                proto.String(""),
			ClientKey:                 proto.String(""),
			QueueLen:                  proto.Uint32(0),
			StartupGc:                 proto.Int32(0),
			StartupInfWaitTimeS:       proto.Uint32(0),
			StartupTickIntervalMs:     proto.Uint32(0),
			StartupLowTicksNeeded:     proto.Uint32(0),
			StartupLowEvtThreshold:    proto.Uint32(0),
			FilterEmpty:               proto.Bool(false),
			SslVerifyCertificate:      proto.Bool(false),
			AuthToken:                 proto.String("/var/run/secrets/kubernetes.io/serviceaccount/token"),
			AnnotationFilter:          make([]string, 0),
			IncludeTypes:              make([]string, 0),
			EventCountsLogTime:        proto.Uint32(0),
			BatchMsgsQueueLen:         proto.Uint32(0),
			BatchMsgsTickIntervalMs:   proto.Uint32(0),
			MaxRndConnDelay:           proto.Uint32(0),
			PodStatusAllowlist:        make([]string, 0),
			ThinCointerface:           proto.Bool(false),
			PodPrefixForCidrRetrieval: make([]string, 0),
			TerminatedPodsEnabled:     proto.Bool(false),
			ColdStartNum:              proto.Uint32(uint32(*numLeases)),
			MaxWaitForLock:            proto.Uint32(0),
			MaxColdStartDuration:      proto.Uint32(0),
			DelegatedNum:              proto.Int32(0),
			LeaderElection: &sdc_internal.LeaderElectionConf{
				LeaseDuration: proto.Uint32(15),
				RenewDeadline: proto.Uint32(10),
				RetryPeriod:   proto.Uint32(2),
				Namespace:     leaseNamespace,
			},
		},
	})

	if err != nil {
		logger.Error(err.Error())
		return
	}

	imReady := false

	http.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		if imReady {
			w.WriteHeader(200)
			w.Write([]byte("OK"))
		} else {
			w.WriteHeader(500)
			w.Write([]byte("K0"))
		}
	})

	http.HandleFunc("/release", func(w http.ResponseWriter, _ *http.Request) {
		client.Release(ctx, &sdc_internal.LeasePoolNull{})
		imReady = false
		w.WriteHeader(200)
		w.Write([]byte("Release called"))
	})

	http.HandleFunc("/leaders", func(w http.ResponseWriter, _ *http.Request) {
		resp, err := client.GetNodesWithLease(ctx, &sdc_internal.LeasePoolNull{})

		dumpError := func(err error) {
			w.WriteHeader(500)
			w.Write([]byte(fmt.Sprintf("Got error %s", err.Error())))
		}

		msg, err := resp.Recv()

		if err != nil {
			dumpError(err)
			return
		}

		ret := strings.Join(msg.Node, ",")

		w.WriteHeader(200)
		w.Write([]byte(ret))
	})

	http.HandleFunc("/lease", func(w http.ResponseWriter, _ *http.Request) {
		wait, err := client.WaitLease(ctx, &sdc_internal.LeasePoolNull{})
		if err != nil {
			fmt.Fprintf(w, "Error: %s", err.Error())
			w.WriteHeader(404)
		} else {
			ret, err := wait.Recv()
			if err != nil {
				fmt.Fprintf(w, "Error: %s", err.Error())
				w.WriteHeader(404)
			} else if *ret.Successful == false {
				fmt.Fprintf(w, "Error: operation unsuccessfull", err.Error())
				w.WriteHeader(404)
			} else {
				w.WriteHeader(200)
				w.Write([]byte("lease called"))
			}
		}
	})

	go func() {
		err := http.ListenAndServe(":"+strconv.Itoa(*heltzPort), nil)
		if err != nil {
			log.Errorf("Could not start http server on port %d: %s", *heltzPort, err.Error())
		}
	}()

	wait, err := client.WaitLease(ctx, &sdc_internal.LeasePoolNull{})

	stopCh := make(chan struct{})
	waitLeader := func() {
		for {
			res, err := wait.Recv()

			if err != nil {
				logger.Debugf("Stream closed. Bye Bye")
				return
			}

			if *res.Successful == true {
				logger.Debugf("Horray!! Got the lease!!!")
				imReady = true
			}

			if *res.Successful == false {
				logger.Debugf("So sad. Got this error: %s", *res.Reason)
				stopCh <- struct{}{}
			}
		}
	}

	if err != nil {
		logger.Error(err.Error())
	} else {
		go waitLeader()
	}

	for {
		select {
		case <-wait.Context().Done():
			logger.Debugf("That's all falks")
			return
		case <-stopCh:
			logger.Debugf("That's all falks")
			return
		}

	}
}
