package k8s_audit

import (
	"cointerface/sdc_internal"
	"encoding/json"
	"github.com/gogo/protobuf/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"
	log "github.com/cihub/seelog"
)

var(
	k8sEvtID  uint64 = 1   // each k8s event have an ID assigned by this module
)

type k8sAuditServer struct {
	evtsChannel chan *sdc_internal.K8SAuditEvent
	initialized bool
	cancel context.CancelFunc
}

func (ks *k8sAuditServer) Init() error {
	ks.evtsChannel = make(chan *sdc_internal.K8SAuditEvent)

	ks.initialized = true

	return nil
}

func (ks *k8sAuditServer) Load(ctx context.Context, load *sdc_internal.K8SAuditServerLoad) (*sdc_internal.K8SAuditServerLoadResult, error) {

	log.Debugf("Received K8s Audit Server Load message: %s", load.String())

	if ! ks.initialized {
		if err := ks.Init(); err != nil {
			return nil, err
		}
	}

	result := &sdc_internal.K8SAuditServerLoadResult{
		Successful: proto.Bool(true),
	}

	r := http.NewServeMux()
	r.Handle("/k8s_audit", ks)

	var s = &http.Server {
		Addr: *load.K8SAuditServerUrl + ":" + strconv.Itoa(int(*load.K8SAuditServerPort)),
		Handler: r,
		ReadTimeout: time.Second * 10,
		WriteTimeout: time.Second * 10,
		MaxHeaderBytes: 1 << 20,
	}


	go func() {
		if err := s.ListenAndServe(); err != nil {
			log.Errorf("K8s Audit Server ListenAndServe(): %s", err)
			result.Successful = proto.Bool(false)
			result.Errstr = proto.String(err.Error())
		}
	}()

	return result, nil
}

func (ks *k8sAuditServer) Start(start *sdc_internal.K8SAuditServerStart, stream sdc_internal.K8SAudit_StartServer) error {
	log.Debugf("Received K8s Audit Start message: %s", start.String())

	if ks.cancel != nil {
		// Start() was previously called. Stop those tasks first.
		ks.cancel()
		ks.cancel = nil
	}

	ctx, cancel := context.WithCancel(context.Background())

	ks.cancel = cancel

	RunTasks:
	for {
		select {
		case evt := <- ks.evtsChannel:
			log.Debugf("Sending K8s Audit Event to agent %s", evt.String())
			if err := stream.Send(evt); err != nil {
				log.Errorf("Could not send event %s: %v",
					evt.String(), err.Error())
				return err
			}
		case <- ctx.Done():
			break RunTasks
		}
	}

	log.Debugf("Returning from K8s Audit Server Start")

	return nil
}

func (ks *k8sAuditServer) Stop(ctx context.Context, load *sdc_internal.K8SAuditServerStop) (*sdc_internal.K8SAuditStopResult, error) {
	log.Debugf("Received K8s Audit Stop message : %s", load.String())

	result := &sdc_internal.K8SAuditStopResult{
		Successful: proto.Bool(true),
	}

	if ! ks.initialized {
		return result, nil
	}

	if ks.cancel != nil {
		ks.cancel()
		ks.cancel = nil
	}

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
				EvtId: proto.Uint64(k8sEvtID),
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

	ks := &k8sAuditServer{}
	ks.Init()

	sdc_internal.RegisterK8SAuditServer(grpcServer, ks)

	return nil
}

