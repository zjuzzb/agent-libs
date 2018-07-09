// Assumes that cmake will set the env vars
//go:generate sh -c "protoc -I ${PROTO_SRC_DIR} --gofast_out=plugins=grpc:${PROTO_OUT_DIR}/draiosproto ${PROTO_SRC_DIR}/draios.proto"
//go:generate sh -c "protoc -I ${PROTO_SRC_DIR} --gofast_out=plugins=grpc,Mdraios.proto=decode_proto/draiosproto:${PROTO_OUT_DIR}/sdc_internal ${PROTO_SRC_DIR}/sdc_internal.proto"

package main
