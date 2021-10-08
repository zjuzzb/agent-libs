package server

import (
	"coldstart_manager/leader_lib"
	"context"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	log "github.com/cihub/seelog"
	"github.com/draios/protorepo/sdc_internal"
	"github.com/gogo/protobuf/proto"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

type leasePoolServer struct {
	name             string
	coldStartManager leader_lib.LeasePoolManager
	maxWaitForLock   uint32
	terminateChan    chan struct{}
}

func (cs *leasePoolServer) Init(ctx context.Context, initCmd *sdc_internal.LeasePoolInit) (*sdc_internal.LeasePoolNull, error) {
	var id string
	if initCmd.Id != nil && *initCmd.Id != "" {
		id = *initCmd.Id
	} else {
		id = uuid.New().String()
	}

	cs.name = *initCmd.LeaseName

	if initCmd.Cmd.MaxWaitForLock != nil {
		cs.maxWaitForLock = *initCmd.Cmd.MaxWaitForLock
	}

	log.Debugf("Init called: %s %s", *initCmd.LeaseName, id)
	// Create the clientset
	kubeClient, err := createKubeClient(initCmd.Cmd.GetUrl(),
		initCmd.Cmd.GetCaCert(),
		initCmd.Cmd.GetClientCert(),
		initCmd.Cmd.GetClientKey(),
		initCmd.Cmd.GetSslVerifyCertificate(),
		initCmd.Cmd.GetAuthToken())
	if err != nil {
		log.Errorf("%s Cannot create k8s client: %s", cs.name, err)
		return nil, err
	}

	cs.coldStartManager.Init(id, *initCmd.LeaseName, *initCmd.LeaseNum, *initCmd.GetCmd().GetLeaderElection(), kubeClient)

	return &sdc_internal.LeasePoolNull{}, nil
}

func (cs *leasePoolServer) WaitLease(none *sdc_internal.LeasePoolNull, stream sdc_internal.LeasePoolManager_WaitLeaseServer) error {
	log.Debugf("%s WaitLease called", cs.name)
	err := cs.coldStartManager.WaitLock(cs.maxWaitForLock, stream.Context())

	if err != nil {
		log.Debugf(err.Error())
		stream.Send(&sdc_internal.LeasePoolWaitResult{
			Successful: proto.Bool(false),
			Reason:     proto.String(err.Error()),
		})
	} else {
		stream.Send(&sdc_internal.LeasePoolWaitResult{
			Successful: proto.Bool(true),
		})
	}
	// Wait for ever. We are supposed to send back lost lease events
	<-stream.Context().Done()
	log.Debugf("%s Wait Lease: Stream context canceled", cs.name)
	cs.Release(context.TODO(), &sdc_internal.LeasePoolNull{})
	cs.terminateChan <- struct{}{}
	return nil

}

func (cs *leasePoolServer) Release(context.Context, *sdc_internal.LeasePoolNull) (*sdc_internal.LeasePoolNull, error) {
	log.Debugf("%s Release called", cs.name)
	cs.coldStartManager.Release()
	return &sdc_internal.LeasePoolNull{}, nil
}

func (cs *leasePoolServer) GetNodesWithLease(none *sdc_internal.LeasePoolNull, stream sdc_internal.LeasePoolManager_GetNodesWithLeaseServer) error {
	leaders := cs.coldStartManager.GetHolderIdentities()

	ret := sdc_internal.LeaseNodes{}
	for _, leader := range leaders {
		ret.Node = append(ret.Node, leader)
	}

	stream.Send(&ret)
	return nil
}

func StartServer(sock string, wg *sync.WaitGroup) int {
	defer wg.Done()
	log.Debugf("Starting leasePoolManager server, grpc version %s, pid %d, socket %s", grpc.Version, os.Getpid(), sock)
	defer log.Debugf("lease_pool_manager exiting, pid %d, socket %s", os.Getpid(), sock)

	listener, err := net.Listen("unix", sock)

	if err != nil {
		log.Criticalf("Could not listen on socket %s: %s", sock, err)
		return 1
	}

	log.Infof("Listening on socket %s for messages", sock)

	grpcServer := grpc.NewServer()
	leaseServer := &leasePoolServer{
		terminateChan: make(chan struct{}),
	}

	defer leaseServer.Release(context.TODO(), &sdc_internal.LeasePoolNull{})
	sdc_internal.RegisterLeasePoolManagerServer(grpcServer, leaseServer)

	// Capture SIGINT and exit gracefully
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGKILL, syscall.SIGTERM)

	go func() {
		select {
		case sig := <-signals:
			log.Debugf("[%s]. Received signal %s, closing listener", sock, sig)
			listener.Close()
		case <-leaseServer.terminateChan:
			log.Debugf("[%s]. dragent terminated. Terminating", sock)
			listener.Close()
		}
	}()

	grpcServer.Serve(listener)

	log.Debugf("lease_pool_manager [%s] exiting", sock)
	return 0
}

func createKubeClient(apiServer string, caCert string, clientCert string, clientKey string, sslVerify bool, authToken string) (kubeClient kubeclient.Interface, err error) {
	skipVerify := !sslVerify
	if skipVerify {
		caCert = ""
	}
	tokenStr := ""
	if authToken != "" {
		tokenBytes, err := ioutil.ReadFile(authToken)
		if err != nil {
			log.Warnf("Unable to read bearer token from %v", authToken)
		} else {
			tokenStr = string(tokenBytes[:])
			// Trailing newlines cause the api server to reject the token
			tokenStr = strings.TrimRight(tokenStr, "\n")
			if tokenStr == "" {
				log.Warn("No token found in bearer token file")
			}
		}
	}

	baseConfig := clientcmdapi.NewConfig()
	configOverrides := &clientcmd.ConfigOverrides{
		ClusterInfo: clientcmdapi.Cluster{
			Server:                apiServer,
			InsecureSkipTLSVerify: skipVerify,
			CertificateAuthority:  caCert,
		},
		AuthInfo: clientcmdapi.AuthInfo{
			ClientCertificate: clientCert,
			ClientKey:         clientKey,
			Token:             tokenStr,
		},
	}
	kubeConfig := clientcmd.NewDefaultClientConfig(*baseConfig, configOverrides)
	config, err := kubeConfig.ClientConfig()
	if err != nil {
		log.Errorf("kubecollect can't create config")
		return nil, err
	}

	kubeClient, err = kubeclient.NewForConfig(config)
	if err != nil {
		log.Errorf("kubecollect NewForConfig fails")
		return nil, err
	}

	return kubeClient, nil
}
