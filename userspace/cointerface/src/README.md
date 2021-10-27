# Cointerface

This directory contains a set of Go modules. The main one is `cointerface`
which is used to extract information inherent to a Kubernetes cluster from the
Apiserver in order to enrich the metrics produced by Sysdig agent.

The main reason why this was part was implemented in Go is to profit from
[client-go](https://github.com/kubernetes/client-go) library.

## Development

Required tools:
* [Go](https://golang.org/doc/install)
* [protoc](https://grpc.io/docs/protoc-installation/)
* [cmake](https://cmake.org/)

The versions used during regular build can be found
[here](../../../../docker/centos-builder/install-deps.sh).

### Build

You can build `cointerface` the following way positioning yourself at the root
of the repository.

1. Generate the makefiles using cmake.

```sh
mkdir -p build && cd build
cmake .. -DGOROOT=$(go env GOROOT) -DGOPATH=$(go env GOPATH)
```

2. Use make to build the binary.

```sh
make cointerface
```

The binary will be located in `build/userspace/cointerface/` directory.

*Note that* the other binaries can be built with the same approach e.g.

```sh
make coclient
```

### Adding dependencies

Cointerface uses [go modules](https://github.com/golang/go/wiki/Modules) to
manage dependencies.

### Run lint

```sh
make golint-cointerface
```

### Run locally

* Run `cointerface`

```sh
build/userspace/cointerface/cointerface -sock /tmp/cointerface-sock
```

* Send `OrchestratorEvnetsStreamCommand` with `coclient`

```
build/userspace/cointerface/coclient -msg orchestrator_event_stream -sock /tmp/cointerface-sock -messagePayloadFile userspace/cointerface/src/coclient/examples/orchestrator_event_stream_sample.json -kubeconfig ~/.kube/config
```

`kubeconfig` should point to the kubeconfig file of the Kubernetes cluster you
are targeting.

At the moment the following authentication schemes are supported:
- client certificate
- token
