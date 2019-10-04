// Assumes that cmake will set the env vars
//go:generate sh -c "protoc -I ${PROTO_SRC_DIR} --gofast_out=plugins=grpc:. ${PROTO_SRC_DIR}/draios.proto"
//go:generate sh -c "protoc -I ${PROTO_SRC_DIR} --gofast_out=plugins=grpc:. ${PROTO_SRC_DIR}/common.proto"

package draiosproto
