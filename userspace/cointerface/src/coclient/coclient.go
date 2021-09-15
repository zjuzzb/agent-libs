package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/draios/install_prefix"
	"github.com/draios/protorepo/sdc_internal"
	"k8s.io/client-go/tools/clientcmd"

	log "github.com/cihub/seelog"
	"github.com/gogo/protobuf/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

type message string

func (m message) String() string {
	return string(m)
}

func (m *message) Set(s string) error {
	switch s {
	case string(messagePing):
		*m = messagePing
	case string(messageDockerCommand):
		*m = messageDockerCommand
	case string(messageOrchestratorEventStream):
		*m = messageOrchestratorEventStream
	default:
		return fmt.Errorf("unrecognized message: %s", s)
	}
	return nil
}

const (
	messagePing                    message = "ping"
	messageDockerCommand           message = "docker_command"
	messageOrchestratorEventStream message = "orchestrator_event_stream"
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: coclient [-sock=<path>] [-msg=<msg>] [-docker_cmd=<command>] [-container=<container id>]\n")
	fmt.Fprintf(os.Stderr, "   <msg> is one of %q, %q, %q\n", messagePing, messageDockerCommand, messageOrchestratorEventStream)
	flag.PrintDefaults()
	os.Exit(1)
}

func initLogging() {
	testConfig := `
<seelog>
  <formats>
    <format id="common" format="%UTCDate(2006-01-02 15:04:05.0000) [%Level] %Msg%n"/>
  </formats>
  <outputs formatid="common">
    <console formatid="common"/>
  </outputs>
</seelog>
`
	logger, err := log.LoggerFromConfigAsBytes([]byte(testConfig))

	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not initialize logger: %s\n", err)
		os.Exit(1)
	}
	_ = log.ReplaceLogger(logger)

}

func unixDialer(ctx context.Context, addr string) (net.Conn, error) {
	log.Debugf("Connecting unix socket: addr=%v", addr)
	d := net.Dialer{}
	return d.DialContext(ctx, "unix", addr)
}

func performDockerCommand(client sdc_internal.CoInterfaceClient, dockerCommand string, container string) error {
	cmd := &sdc_internal.DockerCommand{}

	dcmd := sdc_internal.ContainerCmdType(sdc_internal.ContainerCmdType_value[dockerCommand])
	cmd.Cmd = &dcmd
	cmd.ContainerId = proto.String(container)

	log.Debugf("Docker Command=%s", cmd.String())

	res, err := client.PerformDockerCommand(context.Background(), cmd)

	if err != nil {
		return fmt.Errorf("could not perform docker command: %s", err)
	}

	log.Infof("Result of performing docker command: %s", res.String())

	return nil
}

func performOrchestratorEventStream(client sdc_internal.CoInterfaceClient, msgFile string, kubeconfig string) error {
	cmd := &sdc_internal.OrchestratorEventsStreamCommand{}

	msgPayload, err := ioutil.ReadFile(msgFile)
	if err != nil {
		return fmt.Errorf("could not read message payload file: %v", err)
	}

	if err := json.Unmarshal([]byte(msgPayload), &cmd); err != nil {
		return fmt.Errorf("could not unmarshal message: %v", err)
	}

	if kubeconfig != "" {
		cleanup, err := connInfoFromKubeconfig(cmd, kubeconfig)
		defer cleanup()
		if err != nil {
			return fmt.Errorf("could not extract connection information from kubeconfig: %v", err)
		}
	}

	log.Debugf("OrchestratorEventsStreamCommand=%s", cmd.String())
	res, err := client.PerformOrchestratorEventsStream(context.Background(), cmd)
	if err != nil {
		return fmt.Errorf("could not perform orchestrator events stream: %s", err)
	}

	evt, err := res.Recv()
	if err != nil {
		return fmt.Errorf("error occurred while retrieving update event: %s", err)
	}

	log.Infof("Orchestrator event stream response: %s", evt.GetEvents())

	return nil
}

func connInfoFromKubeconfig(cmd *sdc_internal.OrchestratorEventsStreamCommand, kubeconfig string) (cleanUpFunc func(), err error) {
	cleanUpFunc = func() {}
	k, err := ioutil.ReadFile(kubeconfig)
	if err != nil {
		return cleanUpFunc, fmt.Errorf("could not read kubeconfig file: %v", err)
	}
	conf, err := clientcmd.NewClientConfigFromBytes(k)
	if err != nil {
		return cleanUpFunc, fmt.Errorf("error occurred while parsing kubeconfig: %v", err)
	}
	raw, err := conf.RawConfig()
	if err != nil {
		return cleanUpFunc, fmt.Errorf("error getting raw config: %v", err)
	}
	if raw.CurrentContext == "" {
		return cleanUpFunc, fmt.Errorf("no default context provided in kubeconfig: %s", kubeconfig)
	}
	ctx := raw.Contexts[raw.CurrentContext]

	authInfo := raw.AuthInfos[ctx.AuthInfo]

	// Create temporary directory for storing auth info as the
	// OrchestratorEventsStreamCommand cannot contain the data directly.
	tmpDir, err := ioutil.TempDir(os.TempDir(), "coclient-*")
	if err != nil {
		return cleanUpFunc, fmt.Errorf("error occurred while creating temporary directory for auth info")
	}
	cleanUpFunc = func() {
		os.RemoveAll(tmpDir)
	}

	// Set-up ca cert data and server URL
	cluster := raw.Clusters[ctx.Cluster]
	certAuthDataFile := filepath.Join(tmpDir, "certificate_authority_data")
	*cmd.CaCert = certAuthDataFile
	if err := ioutil.WriteFile(certAuthDataFile, cluster.CertificateAuthorityData, 0600); err != nil {
		return cleanUpFunc, fmt.Errorf("error occurred while trying to write file: %s", err)
	}
	// TODO(irozzo) support proxy URL?
	*cmd.Url = cluster.Server

	// Cert client auth
	switch {
	case authInfo.ClientCertificate != "" && authInfo.ClientKey != "":
		log.Debug("Authenticating with client certificate")
		*cmd.ClientCert, *cmd.ClientKey = authInfo.ClientCertificate, authInfo.ClientKey
	case len(authInfo.ClientCertificateData) > 0 && len(authInfo.ClientKeyData) > 0:
		log.Debug("Authenticating with client certificate data")
		cliCertDataFile := filepath.Join(tmpDir, "client_certificate_data")
		if err := ioutil.WriteFile(cliCertDataFile, authInfo.ClientCertificateData, 0600); err != nil {
			return cleanUpFunc, fmt.Errorf("error occurred while trying to write file: %s", err)
		}
		cliKeyDataFile := filepath.Join(tmpDir, "client_key_data")
		if err := ioutil.WriteFile(cliKeyDataFile, authInfo.ClientKeyData, 0600); err != nil {
			return cleanUpFunc, fmt.Errorf("error occurred while trying to write file: %s", err)
		}
		*cmd.ClientCert, *cmd.ClientKey = cliCertDataFile, cliKeyDataFile
	case authInfo.TokenFile != "":
		log.Debug("Authenticating with token file")
		*cmd.AuthToken = authInfo.TokenFile
	case authInfo.Token != "":
		log.Debug("Authenticating with token")
		tokenFile := filepath.Join(tmpDir, "tokenFile")
		*cmd.AuthToken = tokenFile
		if err := ioutil.WriteFile(tokenFile, []byte(authInfo.Token), 0600); err != nil {
			return cleanUpFunc, fmt.Errorf("error occurred while trying to write file: %s", err)
		}
	default:
		return cleanUpFunc, fmt.Errorf("unsopported authentication scheme")
	}
	return cleanUpFunc, nil
}

func performPing(client sdc_internal.CoInterfaceClient, token int64) error {
	cmd := &sdc_internal.Ping{}

	cmd.Token = proto.Int64(token)

	log.Debugf("Ping=%s", cmd.String())

	res, err := client.PerformPing(context.Background(), cmd)

	if err != nil {
		return fmt.Errorf("Could not perform ping: %s", err)
	}

	log.Infof("Pong response: %s", res.String())

	return nil
}

func mymain() int {
	flag.Usage = usage
	// Default message is ping
	var message = messagePing

	prefix, err := install_prefix.GetInstallPrefix()
	if err != nil {
		_ = log.Errorf("Could not determine installation directory: %s", err)
		return 1
	}
	sockPtr := flag.String("sock", prefix+"/run/cointerface.sock", "domain socket for messages")
	flag.Var(&message, "msg", "Message to send to cointerface")
	tokenPtr := flag.Int64("token", 0, "Token to include in ping message")
	dockerCmdPtr := flag.String("docker_cmd", "", "docker operation to perform on container")
	containerPtr := flag.String("container", "", "container on which to run docker command")
	messageFilePtr := flag.String("messagePayloadFile", "", "file containing message payload in json format("+messageOrchestratorEventStream.String()+" only)")
	kubeconfigFilePtr := flag.String("kubeconfig", "", "path to the kubeconfig file to be used to extract url and auth information for Kube APIServer ("+messageOrchestratorEventStream.String()+" only)")

	flag.Parse()

	// If msg is docker_command, a container must be provided
	if message == messageDockerCommand && *containerPtr == "" {
		fmt.Fprintf(os.Stderr, "A container must be provided when msg=="+messageDockerCommand.String()+"\n")
		usage()
	}

	if message == messageOrchestratorEventStream && *messageFilePtr == "" {
		fmt.Fprintf(os.Stderr, "Payload must be given when msg=="+messageOrchestratorEventStream.String()+"\n")
		usage()
	}

	initLogging()
	defer log.Flush()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, *sockPtr, grpc.WithInsecure(), grpc.WithContextDialer(unixDialer))
	if err != nil {
		_ = log.Errorf("Could not connect to server at %s: %s", *sockPtr, err)
		return 1
	}
	defer conn.Close()

	client := sdc_internal.NewCoInterfaceClient(conn)

	switch message {
	case messagePing:
		err = performPing(client, *tokenPtr)

	case messageDockerCommand:
		err = performDockerCommand(client, *dockerCmdPtr, *containerPtr)

	case messageOrchestratorEventStream:
		err = performOrchestratorEventStream(client, *messageFilePtr, *kubeconfigFilePtr)
	}

	if err != nil {
		_ = log.Errorf("Could not send message: %v", err)
		return 1
	}
	return 0
}

func main() {
	os.Exit(mymain())
}
