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
	void get_swarm_state(response_cb_t response_cb);

	void perform_docker_cmd(sdc_internal::docker_cmd_type cmd,
				const std::string &container_id, response_cb_t response_cb);

	void get_orchestrator_events(sdc_internal::orchestrator_events_stream_command cmd, response_cb_t response_cb);

	// Check for any responses and call their callback functions.
	void next(uint32_t wait_ms = 0);

	// Specify an alternate location for the domain socket. Useful
	// for tests.
	void set_domain_sock(std::string &domain_sock);

	// Clean up any state left around related to the connection to
	// the cointerface process, such as the default unix domain
	// socket.
	//
	// Note: this *only* cleans up the default domain socket, and not
	// any domain socket specified by set_domain_sock().
	static void cleanup();

protected:
	// Set up state for this rpc and perform the rpc.
	void prepare(google::protobuf::Message *request_msg, sdc_internal::cointerface_message_type msgtype,
		     response_cb_t response_cb);

	// Connect to the cointerface process
	void connect();

	struct call_context {

		call_context() : is_streaming(false), is_server_ready(false) {}

		sdc_internal::cointerface_message_type msg_type;

		std::unique_ptr<google::protobuf::Message> response_msg;

		response_cb_t response_cb;

		bool is_streaming;
		bool is_server_ready;

		// This can be used to pass additional options to the server
		// that control how the RPC should be performed (like add
		// compression, set a deadline for a response, etc). We don't
		// use it.
		grpc::ClientContext ctx;
		grpc::Status status;

		// Depending on msg_type, the context will use one of these readers
		std::unique_ptr<grpc::ClientAsyncResponseReader<sdc_internal::pong>> pong_reader;
		std::unique_ptr<grpc::ClientAsyncResponseReader<sdc_internal::docker_command_result>> docker_cmd_result_reader;
		std::unique_ptr<grpc::ClientAsyncResponseReader<sdc_internal::swarm_state_result>> swarm_state_reader;
		std::unique_ptr<grpc::ClientAsyncReader<draiosproto::congroup_update_event>> orchestrator_events_reader;
	};

	// Created by CreateChannel
	std::unique_ptr<sdc_internal::CoInterface::Stub> m_stub;

	grpc::CompletionQueue m_cq;

	google::protobuf::TextFormat::Printer m_print;

	std::string m_domain_sock;
	static std::string default_domain_sock;
	bool m_outstanding_swarm_state;
};
