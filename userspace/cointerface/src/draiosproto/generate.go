// Assumes that cmake will set the env vars
//go:generate sh -c "protoc -I ${PROTO_BIN_DIR} --gofast_out=plugins=grpc:${PROTO_OUT_DIR} ${PROTO_BIN_DIR}/draios.proto"
//go:generate sh -c "protoc -I ${PROTO_BIN_DIR} --gofast_out=plugins=grpc:${PROTO_OUT_DIR} ${PROTO_BIN_DIR}/common.proto"

package draiosproto
