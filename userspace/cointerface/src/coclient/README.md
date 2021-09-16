# Usage

## Quickstart

### Prerequisites

Coclient expects the Protobuf generated Go model to be located at the root of
repository with the following structure.

```
build/
└── generated-go
    ├── draiosproto
    │   ├── generate.go
    │   ├── go.mod
    │   └── protorepo
    │       └── agent-be
    │           └── proto
    │               ├── common.pb.go
    │               ├── draios.pb.go
    │               └── go.mod
    ├── promex_pb
    │   ├── generate.go
    │   ├── go.mod
    │   └── promex.pb.go
    └── sdc_internal
        ├── generate.go
        ├── go.mod
        └── sdc_internal.pb.go
```

You can use the script located [here](../../../../scripts/generate_go_proto.sh)
to generate the Go model, after having ensured that the dependencies are
installed:

#### Install Go

<https://golang.org/doc/install>

#### Install protoc

<https://grpc.io/docs/protoc-installation/#install-pre-compiled-binaries-any-os>

#### Install protoc-gen-gofast

```
go install github.com/gogo/protobuf/protoc-gen-gofast@v1.3.2
```

### Build

To build coclient use the following command:

```
cd userspace/cointerface/src/coclient && go build .
```

## Perform OrchestratorEventsStreamCommand

After starting the cointerface locally you can trigger an
`OrchestratorEventsStreamCommand` with the following command after exporting
the path to the cointerface unix domain socket with `COINTERFACE_UDS`
environment variable.

```
./coclient -msg orchestrator_event_stream -sock "${COINTERFACE_UDS}" -messagePayloadFile examples/orchestrator_event_stream_sample.json -kubeconfig ~/.kube/config
```

`kubeconfig` should point to the kubeconfig file of the Kubernetes cluster you
are targeting.

At the moment the following authentication schemes are supported:
- client certificate
- token
