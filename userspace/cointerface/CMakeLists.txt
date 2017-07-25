set(GOPATH "${CMAKE_CURRENT_BINARY_DIR}:${CMAKE_CURRENT_SOURCE_DIR}")

add_custom_target(go_get_gogo DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/gogo-go-get-complete.txt)
add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/gogo-go-get-complete.txt
                   COMMAND mkdir -p ${CMAKE_CURRENT_BINARY_DIR}/src
                   COMMAND env GOPATH=${GOPATH} go get -u github.com/gogo/protobuf/protoc-gen-gofast
                   COMMAND env GOPATH=${GOPATH} go get -u github.com/gogo/protobuf/proto
		   # horrific hack, fix this
                   COMMAND env GOPATH=${GOPATH} go get -u k8s.io/apimachinery/pkg/apis/meta/v1
                   COMMAND env GOPATH=${GOPATH} go get -u k8s.io/apimachinery/pkg/labels
                   COMMAND env GOPATH=${GOPATH} go get -u k8s.io/apimachinery/pkg/util/runtime
                   COMMAND env GOPATH=${GOPATH} go get -u k8s.io/apimachinery/pkg/util/wait
                   COMMAND env GOPATH=${GOPATH} go get -u k8s.io/api/authentication/v1
		   COMMAND env GOPATH=${GOPATH} go get -u k8s.io/api/core/v1
                   COMMAND env GOPATH=${GOPATH} go get -u k8s.io/client-go/tools/clientcmd
                   COMMAND env GOPATH=${GOPATH} go get -u k8s.io/client-go/tools/clientcmd/api
		   COMMAND env GOPATH=${GOPATH} go get -u k8s.io/client-go/tools/cache
		   COMMAND env GOPATH=${GOPATH} go get -u k8s.io/client-go/kubernetes
		   COMMAND env GOPATH=${GOPATH} go get -u k8s.io/client-go/rest
		   COMMAND env GOPATH=${GOPATH} go get -u k8s.io/client-go/discovery
                   COMMAND touch ${CMAKE_CURRENT_BINARY_DIR}/gogo-go-get-complete.txt)

#add_custom_target(go_get_kubecollect DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/k8s-collectors-go-get-complete.txt)
#add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/k8s-collectors-go-get-complete.txt
#                   DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/src/sdc_internal/sdc_internal.pb.go
#                   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/kubecollect/pod.go
#		   COMMAND env GOPATH=${GOPATH} go fmt kubecollect
#		   COMMAND env GOPATH=${GOPATH} go install kubecollect
#		   COMMAND echo ${GOPATH}
#		   COMMAND echo ${GOBIN}
#		   COMMAND touch ${CMAKE_CURRENT_BINARY_DIR}/k8s-collectors-go-get-complete.txt)

add_custom_target(go_get_cointerface_coclient
                  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/cointerface-coclient-go-get-complete.txt)
add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/cointerface-coclient-go-get-complete.txt
                   DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/src/sdc_internal/sdc_internal.pb.go
                           ${CMAKE_CURRENT_BINARY_DIR}/src/draiosproto/draios.pb.go
#                           go_get_kubecollect
                   COMMAND env GOPATH=${GOPATH} go get cointerface
                   COMMAND env GOPATH=${GOPATH} go get coclient
                   COMMAND touch ${CMAKE_CURRENT_BINARY_DIR}/cointerface-coclient-go-get-complete.txt)

add_custom_target(cointerface ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/cointerface)
add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/cointerface
        COMMAND env GOPATH=${GOPATH} go fmt cointerface
        COMMAND env GOPATH=${GOPATH} go build -o "${CMAKE_CURRENT_BINARY_DIR}/cointerface" cointerface
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
	DEPENDS go_get_cointerface_coclient
	        ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/cointerface.go
                ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/server.go
                ${CMAKE_CURRENT_SOURCE_DIR}/src/cointerface/swarm.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/kubecollect/client.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/kubecollect/deployments.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/kubecollect/pods.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/kubecollect/namespaces.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/kubecollect/nodes.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/kubecollect/replicasets.go
		${CMAKE_CURRENT_SOURCE_DIR}/src/kubecollect/services.go
                ${CMAKE_CURRENT_BINARY_DIR}/src/sdc_internal/sdc_internal.pb.go
                ${CMAKE_CURRENT_BINARY_DIR}/src/draiosproto/draios.pb.go)

add_custom_target(coclient ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/coclient)
add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/coclient
        COMMAND env GOPATH=${GOPATH} go fmt coclient
        COMMAND env GOPATH=${GOPATH} go build -o "${CMAKE_CURRENT_BINARY_DIR}/coclient" coclient
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
	DEPENDS go_get_cointerface_coclient
	        ${CMAKE_CURRENT_SOURCE_DIR}/src/coclient/coclient.go
                ${CMAKE_CURRENT_BINARY_DIR}/src/sdc_internal/sdc_internal.pb.go
                ${CMAKE_CURRENT_BINARY_DIR}/src/draiosproto/draios.pb.go
		cointerface)

set(PROTOC_CMDLINE env PATH=${CMAKE_CURRENT_BINARY_DIR}/bin:$$PATH
                   LD_LIBRARY_PATH=${DRAIOS_DEPENDENCIES_DIR}/protobuf-3.1.0/target/lib
                   ${DRAIOS_DEPENDENCIES_DIR}/protobuf-3.1.0/target/bin/protoc
                   -I ${PROJECT_SOURCE_DIR}/userspace/draiosproto)

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/src/sdc_internal/sdc_internal.pb.go
	DEPENDS go_get_gogo
	COMMENT "Building sdc_internal.pb.go from .proto files"
	DEPENDS ${PROJECT_SOURCE_DIR}/userspace/draiosproto/sdc_internal.proto ${PROJECT_SOURCE_DIR}/userspace/draiosproto/draios.proto
	COMMAND mkdir -p ./sdc_internal
	COMMAND ${PROTOC_CMDLINE}
	        --gofast_out=plugins=grpc,Mdraios.proto=draiosproto:./sdc_internal
		${PROJECT_SOURCE_DIR}/userspace/draiosproto/sdc_internal.proto
		WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/src)

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/src/draiosproto/draios.pb.go
	DEPENDS go_get_gogo
	COMMENT "Building draiosproto.pb.go from .proto files"
	DEPENDS ${PROJECT_SOURCE_DIR}/userspace/draiosproto/draios.proto
	COMMAND mkdir -p ./draiosproto
	COMMAND ${PROTOC_CMDLINE}
	        --gofast_out=plugins=grpc:./draiosproto
                ${PROJECT_SOURCE_DIR}/userspace/draiosproto/draios.proto
	WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/src)

# Note that we don't package the client. That's only for testing
# purposes.
install(DIRECTORY
	DESTINATION /opt/draios/run
	COMPONENT agent)

install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/cointerface
	DESTINATION ${DRAIOS_BIN_PREFIX}/bin
	COMPONENT agent)


