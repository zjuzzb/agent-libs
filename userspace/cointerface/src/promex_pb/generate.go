// Assumes that cmake will set the env vars
//go:generate sh -c "protoc -I ${PROTO_SRC_DIR} -I ${PROTO_BIN_DIR} --gofast_out=plugins=grpc,Mdraios.proto=protorepo/agent-be/proto:${PROTO_OUT_DIR} ${PROTO_SRC_DIR}/promex.proto"

package promex_pb
