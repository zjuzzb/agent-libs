package k8s_audit

import (
	"cointerface/sdc_internal"
	"encoding/json"
	"github.com/gogo/protobuf/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"io/ioutil"
	"net/http"
	"time"
	log "github.com/cihub/seelog"
)

var(
	k8sEvtID  uint64 = 0   // each k8s event have an ID assigned by this module
)

type k8sAuditServer struct {
	customerId string
	machineId string

	evtsChannel chan *sdc_internal.K8SAuditEvent
	// Send a value to this channel to stop any previous start
	stopTasksChannel chan bool

	// Read the results of the stop from this channel after writing to tasksChannel
	stopTasksDoneChannel chan error

}

func (ks *k8sAuditServer) Init() error {
	ks.stopTasksChannel = make(chan bool)
	ks.stopTasksDoneChannel = make(chan error)
	ks.evtsChannel = make(chan *sdc_internal.K8SAuditEvent)
	return nil
}

func (ks *k8sAuditServer) Start (start *sdc_internal.K8SAuditServerStart, stream sdc_internal.K8SAudit_StartServer) error {
	log.Debugf("Received K8s Audit Start message: %s", start.String())
	RunTasks:
	for {
		select {
		case evt := <- ks.evtsChannel:
			if err := stream.Send(evt); err != nil {
				log.Errorf("Could not send event %s: %v",
					evt.String(), err.Error())
				return err
			}
		case <- ks.stopTasksChannel:
			break RunTasks
		}
	}

	log.Debugf("Returning from k8s audit Start")

	return nil
}

func (ks *k8sAuditServer) Stop (ctx context.Context, load *sdc_internal.K8SAuditServerStop) (*sdc_internal.K8SAuditStopResult, error) {
	log.Debugf("Received K8s Audit Stop message : %s", load.String())
	result := &sdc_internal.K8SAuditStopResult{
		Successful: proto.Bool(true),
	}

	ks.stopTasksChannel <- true

	log.Debugf("Returning from K8s Audit Stop: %v", result)

	return result, nil
}

func (ks *k8sAuditServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var message string

	switch r.Method {
	case http.MethodPost:
		var j json.RawMessage
		jsn, err := ioutil.ReadAll(r.Body)

		if (err != nil) {
			log.Errorf("Invalid K8s audit event: error while reading")
			w.WriteHeader(http.StatusInternalServerError)
			message = "Invalid Body"
		} else if err := json.Unmarshal(jsn, &j); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			message = "Malformed JSON\n"
		} else {
			// Create a new record.
			evt := &sdc_internal.K8SAuditEvent{
				TaskName: proto.String("k8s-evt-" + string(k8sEvtID)),
				EvtJson: proto.String(string(jsn[:])),
				Successful: proto.Bool(true),
			}
			k8sEvtID += 1 // it's ok if we overflow
			message = "<html><body>Ok</body></html>"
			ks.evtsChannel <- evt
		}
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		message = "Method " + string(r.Method) + " not allowed\n"
	}

	w.Write([]byte(message))
}

func Register(grpcServer *grpc.Server) error {

	ks := &k8sAuditServer{
	}
	ks.Init()

	r := http.NewServeMux()
	r.Handle("/k8s_audit", ks)

	var s = &http.Server {
		Addr: "127.0.0.1:8765",
		Handler: r,
		ReadTimeout: time.Second * 10,
		WriteTimeout: time.Second * 10,
		MaxHeaderBytes: 1 << 20,
	}


	sdc_internal.RegisterK8SAuditServer(grpcServer, ks)

	// s.HandleFunc("/k8s_audit", ks.handleK8sAuditEvents)
	go func() {
		if err := s.ListenAndServe(); err != nil {
			panic(err)
		}
	}()

	return nil
}

