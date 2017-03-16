// Interface to handle grpc with cointerface subprocess.
// Alternatively, you can directly use the grpc async classes
// directly. This wrapper might be a bit easier to use.

#pragma once

#include <functional>
#include <memory>
#include <string>

#include <grpc++/grpc++.h>
#include <google/protobuf/text_format.h>

#include "sdc_internal.pb.h"
#include "sdc_internal.grpc.pb.h"

// This generally follows the example at
// https://github.com/grpc/grpc/blob/v1.0.0/examples/cpp/helloworld/greeter_async_client2.cc,
// but has shared code to handle the async mechanics.

// If you're looking for a async + streaming example, there isn't one
// in the general grpc tutorials, but there is one at
// https://github.com/grpc/grpc/pull/8934/files.

class coclient
{
public:
	// This function will be called with the response to the rpc.
	typedef std::function<void(bool successful, google::protobuf::Message *response_msg)> response_cb_t;

	coclient();
	virtual ~coclient();

	void ping(int64_t token, response_cb_t response_cb);

	// Check for any responses and call their callback functions.
	void next();

protected:

	// Set up state for this rpc and perform the rpc.
	void prepare(google::protobuf::Message *request_msg, sdc_internal::cointerface_message_type msgtype,
		     response_cb_t response_cb);

	// Connect to the cointerface process
	void connect();

	struct call_context {
		sdc_internal::cointerface_message_type msg_type;

		unique_ptr<google::protobuf::Message> response_msg;

		response_cb_t response_cb;

		// This can be used to pass additional options to the server
		// that control how the RPC should be performed (like add
		// compression, set a deadline for a response, etc). We don't
		// use it.
		grpc::ClientContext ctx;
		grpc::Status status;

		// Depending on msg_type, the context will use one of these readers
		std::unique_ptr<grpc::ClientAsyncResponseReader<sdc_internal::pong>> pong_reader;
	};

	// Created by CreateChannel
	std::unique_ptr<sdc_internal::CoInterface::Stub> m_stub;

	grpc::CompletionQueue m_cq;

	google::protobuf::TextFormat::Printer m_print;
};
