package k8s_audit

import (
	"fmt"

	"github.com/draios/protorepo/sdc_internal"
	"crypto/tls"
	"github.com/gogo/protobuf/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	cancel           context.CancelFunc

	// When cancel is non-nil, a Stop() will send a message on
	// this channel when the Stop() is complete.
	cancelDone       chan bool
}

type k8sAuditHttpHandler struct {
	evtsChannel       chan<- *sdc_internal.K8SAuditEvent
}

func (ks *k8sAuditServer) Start(start *sdc_internal.K8SAuditServerStart, stream sdc_internal.K8SAudit_StartServer) error {

	log.Infof("Received K8s Audit Start message: %s", start.String())

	ctx := context.Background()

	_, err := ks.Stop(ctx, &sdc_internal.K8SAuditServerStop{}); if err != nil {
		errmsg := fmt.Sprintf("Stop() returned error: %v", err)
		log.Errorf("K8s Audit Start: %s", errmsg)
		return status.Error(codes.FailedPrecondition, errmsg)
	}

	evtsChannel := make(chan *sdc_internal.K8SAuditEvent, 16)
	auditHttpHandler := &k8sAuditHttpHandler{
		evtsChannel: evtsChannel,
	}

	/* common HTTP/HTTPS configuration */
	httpHandler := http.NewServeMux()
	for _, path := range start.PathUris {
		httpHandler.Handle(path, auditHttpHandler)
	}
	httpServer := &http.Server {
		Addr: start.GetUrl() + ":" + strconv.Itoa(int(start.GetPort())),
		Handler: httpHandler,
		ReadTimeout: time.Second * 10,
		WriteTimeout: time.Second * 10,
		MaxHeaderBytes: 1 << 20,
	}

	/* HTTP only (TLS is disabled) */
	if  start.GetTlsEnabled() == false {
		log.Infof("K8s Audit Server setting up endpoint over HTTP: %v", httpServer.Addr)

		go func(){
			if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
				// This only returns when the server has an error or is cancelled
				errmsg := fmt.Sprintf("ListenAndServe returned error: %v", err)
				log.Errorf("K8s Audit Start: %s", errmsg)
			}
		}()
	} else {  /* HTTPS */
		log.Infof("K8s Audit Server listening for K8s Audit Events over HTTPS: %v", httpServer.Addr)

		/* Validate X509 object is present */
		x509 := start.GetX509()

		if x509 == nil {
			errmsg := "GetX509(): X509 object is not present"
			log.Errorf("K8s Audit Start: %s", errmsg)
			return status.Error(codes.InvalidArgument, errmsg)
		}
		/* Validation on the number of x509 objs */
		if len(x509) > 3 {
			errmsg := "Validate x509 object: too many certificates provided (max is 3)"
			log.Errorf("K8s Audit Start: %s", errmsg)
			return status.Error(codes.InvalidArgument, errmsg)
		}

		cfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}

		for i := 0 ; i < len(x509) ; i++ {
			log.Debugf("Loading X509 private key certificate: {cert file: %s, key file: %s}",
				*x509[i].X509CertFile, *x509[i].X509KeyFile)
			cert, err := tls.LoadX509KeyPair(
				*x509[i].X509CertFile,
				*x509[i].X509KeyFile)

			if err != nil {
				errmsg := fmt.Sprintf("Could not load tls X509KeyPair(): %v", err)
				log.Errorf("K8s Audit Start: %s", errmsg)
				return status.Error(codes.InvalidArgument, errmsg)
			}

			cfg.Certificates = append(cfg.Certificates, cert)
		}

		cfg.BuildNameToCertificate()

		httpServer.TLSConfig = cfg

		// passing empty string to ListenAndServeTLS, as we
		// specify the location of the certificate in the tls
		// config, as reference please see:
		// https://github.com/golang/go/commit/f81f6d6ee8a7f578ab19ccb8b7dbc3b6fff81aa0
		go func(){
			if err := httpServer.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
				// This only returns when the server has an error or is cancelled
				errmsg := fmt.Sprintf("ListenAndServeTLS returned error: %v", err)
				log.Errorf("K8s Audit Start: %s", errmsg)
			}
		}()
	}

	// The http server was started in the background above. Now
	// read responses from it over evtsChannel until stopped.
	evtsCtx, cancel := context.WithCancel(ctx)

	ks.cancelDone = make(chan bool)
	ks.cancel = cancel

	RunTasks:
	for {
		select {
		case evt := <- evtsChannel:
			log.Debugf("Sending K8s Audit Event to agent %d", evt.GetEvtId())
			if err := stream.Send(evt); err != nil {
				log.Errorf("Could not send event %s: %v",
					evt.GetEvtId(), err.Error())
			}
		case <- evtsCtx.Done():
			log.Infof("Received K8S Audit Stop() notification, shutting down http server")
			shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 10 * time.Second)
			defer shutdownCancel()
			if err := httpServer.Shutdown(shutdownCtx); err != nil {
				errmsg := fmt.Sprintf("Shutdown returned error: %v", err)
				log.Errorf("K8s Audit Start: %s", errmsg)
				return status.Error(codes.FailedPrecondition, errmsg)
			}
			break RunTasks
		}
	}

	log.Infof("K8s Audit Start: exiting")
	ks.cancelDone <- true

	return nil
}

func (ks *k8sAuditServer) Stop(ctx context.Context, stop *sdc_internal.K8SAuditServerStop) (*sdc_internal.K8SAuditServerStopResult, error) {
	log.Infof("Received K8s Audit Stop message : %s", stop.String())

	result := &sdc_internal.K8SAuditServerStopResult{
		Successful: proto.Bool(true),
	}

	if ks.cancel != nil {
		log.Infof("Cancelling prior K8s Audit Start()")
		ks.cancel()
		_ = <- ks.cancelDone
		ks.cancel = nil
		ks.cancelDone = nil
	}

	log.Debugf("Returning from K8s Audit Stop: %v", result)

	return result, nil
}

func (ks *k8sAuditHttpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var message string

	switch r.Method {
	case http.MethodPost:
		jsn, err := ioutil.ReadAll(r.Body)

		if (err != nil) {
			log.Errorf("Invalid K8s audit event: error while reading")
			w.WriteHeader(http.StatusInternalServerError)
			message = "Invalid Body"
		} else {
			log.Debugf("K8s Audit Post Received (%d bytes)", len(jsn))

			// Create a new record.
			evt := &sdc_internal.K8SAuditEvent{
				EvtId: proto.Uint64(k8sEvtID),
				EvtJson: proto.String(string(jsn[:])),
			}
			k8sEvtID += 1 // it's ok if we overflow
			message = "<html><body>Ok</body></html>"
			select {
			case ks.evtsChannel <- evt:
			default:
				log.Errorf("Dropping Audit Content (buffer full)")
			}
		}
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		message = "Method " + string(r.Method) + " not allowed\n"
	}

	w.Write([]byte(message))
}

func Register(grpcServer *grpc.Server) error {

	ks := &k8sAuditServer{}

	sdc_internal.RegisterK8SAuditServer(grpcServer, ks)

	return nil
}

