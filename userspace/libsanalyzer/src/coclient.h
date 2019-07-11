// Interface to handle grpc with cointerface subprocess.
// Alternatively, you can directly use the grpc async classes
// directly. This wrapper might be a bit easier to use.

#ifndef CYGWING_AGENT
#pragma once

#include <functional>
#include <memory>
#include <string>

#include <grpc++/grpc++.h>
#include <google/protobuf/text_format.h>
#include <Poco/File.h>

// From sysdig, for g_logger
#include "sinsp.h"
#include "sinsp_int.h"
#include "common_logger.h"
#include "grpc_channel_registry.h"

#include "sdc_internal.grpc.pb.h"

// This generally follows the example at
// https://github.com/grpc/grpc/blob/v1.0.0/examples/cpp/helloworld/greeter_async_client2.cc,
// but has shared code to handle the async mechanics.

// If you're looking for a async + streaming example, there isn't one
// in the general grpc tutorials, but there is one at
// https://github.com/grpc/grpc/pull/8934/files.

// The basic workflow for gRPC is:
// * create a connection and hold on to it forever (gRPC will handle disconnects/reconnects)
// * for every call, get a fresh `unary_grpc_client` (or `streaming_grpc_client`)
// * call client->do_rpc(request, [callback]) to start the remote call
// * call client->process_queue([callback]) repeatedly until:
//   - for unary RPC, your callback gets called
//   - for streaming RPC, your callback gets called with streaming_grpc::SHUTDOWN as the first argument
//
// If you delete the client object before the RPC finishes, gRPC will log an error message
// but shouldn't cause memory safety problems (e.g. null deref or use after free)

template<class Stub> std::shared_ptr<Stub> grpc_connect(const std::string& socket_url)
{
	g_logger.log("CONNECTING TO SOCKET " + socket_url, sinsp_logger::SEV_INFO);
	return make_shared<Stub>(libsinsp::grpc_channel_registry::get_channel(socket_url));
}

template<class Stub> std::shared_ptr<Stub> grpc_connect(const std::string& socket_url, int connect_timeout_ms)
{
	g_logger.log("CONNECTING TO SOCKET " + socket_url, sinsp_logger::SEV_DEBUG);

	auto channel = libsinsp::grpc_channel_registry::get_channel(socket_url);
	auto deadline = gpr_time_add(gpr_now(GPR_CLOCK_MONOTONIC), gpr_time_from_millis(connect_timeout_ms, GPR_TIMESPAN));
	bool connected = channel->WaitForConnected(deadline);
	if(connected)
	{
		g_logger.log("Connected to " + socket_url, sinsp_logger::SEV_INFO);
		return make_shared<Stub>(channel);
	}
	else
	{
		g_logger.log("Failed to connect to " + socket_url, sinsp_logger::SEV_WARNING);
		return nullptr;
	}
}

template <typename R, typename S, typename C, typename W, typename Q> S get_unary_stub_type(unique_ptr<grpc::ClientAsyncResponseReader<R>> (S::*)(C, const W&, Q));
template <typename R, typename S, typename C, typename W, typename Q> W get_unary_request_type(unique_ptr<grpc::ClientAsyncResponseReader<R>> (S::*)(C, const W&, Q));
template <typename R, typename S, typename C, typename W, typename Q> R get_unary_response_type(unique_ptr<grpc::ClientAsyncResponseReader<R>> (S::*)(C, const W&, Q));
#define unary_grpc_client(Method) unary_grpc_client_<decltype(get_unary_request_type(Method)), decltype(get_unary_response_type(Method)), decltype(get_unary_stub_type(Method)), Method>

template<class RequestMsg, class ResponseMsg, class Stub, unique_ptr<grpc::ClientAsyncResponseReader<ResponseMsg>> (Stub::*Method)(grpc::ClientContext*, const RequestMsg&, grpc::CompletionQueue*)>
class unary_grpc_client_
{
public:
	typedef std::function<void(bool successful, ResponseMsg &response_msg)> response_cb_t;

        unary_grpc_client_(std::shared_ptr<Stub> stub):
                m_stub(stub),
		m_response_cb(nullptr),
		m_busy(false),
		m_cb_pending(false)
	{
	}

	virtual ~unary_grpc_client_()
	{
	}

	// Read up to max_loop_evts from the rpc response queue
	// Returns true unless we drain the queue or detect a shutdown
	bool process_queue(response_cb_t response_cb, uint32_t max_loop_evts = 100)
	{
		if (m_cb_pending && response_cb) {
			response_cb(m_status.ok(), m_response_msg);
			m_cb_pending = false;
			return false;
		}

		uint32_t count = 0;
		bool okay = true;
		while (okay && count < max_loop_evts)
		{
			okay = next(response_cb);
			count++;
		}
		return okay;
	}
	bool process_queue()
	{
		return process_queue(m_response_cb);
	}

	// Perform the streaming rpc identified by method, passing the
	// provided request_msg as argument. As responses are
	// available, they will be passed back using response_cb.
	void do_rpc(RequestMsg &request_msg, response_cb_t response_cb=nullptr)
	{
		m_response_cb = response_cb;
		m_ctx.reset(new grpc::ClientContext());
		m_cq.reset(new grpc::CompletionQueue());
		m_busy = true;

		m_reader = ((*m_stub.get()).*Method)(m_ctx.get(), request_msg, m_cq.get());

		// Tell the reader to write the response into the response
		// message and update status with whether or not the rpc could be
		// performed
		m_reader->Finish(&m_response_msg, &m_status, (void*)NULL);
		process_queue();
	}

	bool busy() const { return m_busy; }

protected:

	void handle_event(bool updates_ok, response_cb_t response_cb)
	{
		if (!updates_ok) {
			// todo: report error
			return;
		}

		if (response_cb) {
			response_cb(m_status.ok(), m_response_msg);
		} else {
			m_cb_pending = true;
		}
		m_busy = false;
	}

	// Check for any responses and call their callback functions.
	// Returns true if there are possibly more events to read
	bool next(response_cb_t response_cb)
	{
		void *tag = NULL;
		bool updates_ok;
		grpc::CompletionQueue::NextStatus status;

		if(!m_cq)
		{
			return false;
		}

		status = m_cq->AsyncNext(&tag, &updates_ok, gpr_time_0(GPR_CLOCK_MONOTONIC));
		if(status == grpc::CompletionQueue::SHUTDOWN)
		{
			g_logger.log("server process shut down, disconnecting", sinsp_logger::SEV_ERROR);
			return false;
		}
		else if(status == grpc::CompletionQueue::TIMEOUT)
		{
			return false;
		}

		handle_event(updates_ok, response_cb);
		return true;
	}

	std::shared_ptr<Stub> m_stub;
	unique_ptr<grpc::CompletionQueue> m_cq;

	unique_ptr<grpc::ClientAsyncResponseReader<ResponseMsg>> m_reader;
	// This can be used to pass additional options to the server
	// that control how the RPC should be performed (like add
	// compression, set a deadline for a response, etc). We don't
	// use it.
	unique_ptr<grpc::ClientContext> m_ctx;
	grpc::Status m_status;
	ResponseMsg m_response_msg;
	response_cb_t m_response_cb;
	bool m_busy;
	bool m_cb_pending;
};

template <typename R, typename S, typename C, typename W, typename Q, typename V> S get_streaming_stub_type(std::unique_ptr<grpc::ClientAsyncReader<R>> (S::*)(C, const W&, Q, V));
template <typename R, typename S, typename C, typename W, typename Q, typename V> W get_streaming_request_type(std::unique_ptr<grpc::ClientAsyncReader<R>> (S::*)(C, const W&, Q, V));
template <typename R, typename S, typename C, typename W, typename Q, typename V> R get_streaming_response_type(std::unique_ptr<grpc::ClientAsyncReader<R>> (S::*)(C, const W&, Q, V));
#define streaming_grpc_client(Method) streaming_grpc_client_<decltype(get_streaming_request_type(Method)), decltype(get_streaming_response_type(Method)), decltype(get_streaming_stub_type(Method)), Method>

struct streaming_grpc {
	enum Status {
		OK = 0,
		ERROR,
		SHUTDOWN
	};
};

template<class RequestMsg, class ResponseMsg, class Stub, std::unique_ptr<grpc::ClientAsyncReader<ResponseMsg>> (Stub::*Method)(grpc::ClientContext*, const RequestMsg&, grpc::CompletionQueue*, void *)>
class streaming_grpc_client_
{
public:
	typedef std::function<void(streaming_grpc::Status status, ResponseMsg &esponse_msg)> response_cb_t;

	enum State {

		// Have not called method yet, or there was an error
		// calling/reading. do_rpc must be called first.
		STATE_CLOSED = 1,

                // Have called method and is waiting for notification that method was
                // called successfully
		STATE_INIT,

		// Method was called successfully, now reading first response
		STATE_INITIAL_READ,

		// Reading additional responses
		STATE_ADDL_READ,

		// In the middle of shutting down
		STATE_CLOSING
	};


        streaming_grpc_client_(std::shared_ptr<Stub> stub):
                m_stub(stub),
		m_response_cb(nullptr),
		m_state(STATE_CLOSED)

	{
	}

	virtual ~streaming_grpc_client_()
	{
		stop_rpc();
	}

	// Read up to max_loop_evts from the rpc response queue
	// Returns true unless we drain the queue or detect a shutdown
	bool process_queue(uint32_t max_loop_evts = 100)
	{
		if(m_state == STATE_CLOSED)
		{
			return true;
		}

		uint32_t count = 0;
		bool okay = true;
		while (okay && count < max_loop_evts)
		{
			okay = next();
			count++;
		}
		return okay;
	}

	// Perform the streaming rpc identified by method, passing the
	// provided request_msg as argument. As responses are
	// available, they will be passed back using response_cb.
	void do_rpc(RequestMsg &request_msg, response_cb_t response_cb)
	{
		stop_rpc();
		m_ctx.reset(new grpc::ClientContext());
		m_cq.reset(new grpc::CompletionQueue());
		m_response_cb = response_cb;
		m_state = STATE_INIT;
		m_reader = ((*m_stub.get()).*Method)(m_ctx.get(), request_msg, m_cq.get(), this);

		// Call process_queue() internally immediately, to
		// force along the process of sending the request and
		// possibly even getting the response.
		process_queue();
	}

protected:

	// Cancel any previous RPC and drain all its messages from the completion queue.
	void stop_rpc()
	{
		if(m_cq)
		{
			if(m_state == STATE_CLOSED)
			{
				return;
			}

			m_ctx->TryCancel();

			m_state = STATE_CLOSING;

			while(m_state != STATE_CLOSED)
			{
				next();
			}
		}

		// Free the reader now. Valgrind complains about
		// double-deletes if the context is freed before the
		// reader.
		m_reader = NULL;
	}

	// Check for any responses and call their callback functions.
	// Returns true if there are possibly more events to read
	bool next()
	{
		void *tag = NULL;
		bool updates_ok;
		grpc::CompletionQueue::NextStatus status;

		if (!m_cq)
		{
			return false;
		}

		status = m_cq->AsyncNext(&tag, &updates_ok, gpr_time_0(GPR_CLOCK_MONOTONIC));
		if(status == grpc::CompletionQueue::SHUTDOWN)
		{
			g_logger.log("server process shut down, disconnecting", sinsp_logger::SEV_ERROR);
			m_state = STATE_CLOSED;
			return false;
		}
		else if(status == grpc::CompletionQueue::TIMEOUT)
		{
			return false;
		}

		if(!updates_ok)
		{
			switch (m_state) {
			case STATE_INIT:
			case STATE_INITIAL_READ:
				g_logger.log("cointerface streaming RPC returned error", sinsp_logger::SEV_WARNING);

				// Note: response_msg is not valid
				m_response_cb(streaming_grpc::ERROR, m_response_msg);
				break;
			case STATE_ADDL_READ:
			case STATE_CLOSING:
				g_logger.log("cointerface streaming RPC shut down connection", sinsp_logger::SEV_DEBUG);

				// Note: response_msg is not valid
				m_response_cb(streaming_grpc::SHUTDOWN, m_response_msg);
				break;

			case STATE_CLOSED:
			default:
				g_logger.log("cointerface streaming RPC returned error in closed state", sinsp_logger::SEV_WARNING);
				break;
			}

			m_state = STATE_CLOSED;
			return false;
		}

		switch (m_state) {
		case STATE_INIT:

			// Now connected. Read the first
			// response. When AsyncNext returns again, the
			// read is complete.
			m_state = STATE_INITIAL_READ;
			m_response_msg.Clear();
			m_reader->Read(&m_response_msg, this);

			break;

		case STATE_INITIAL_READ:
		case STATE_ADDL_READ:

			// The previously requested read has
			// completed. Call the callback and schedule
			// another read.
			m_state = STATE_ADDL_READ;
			m_response_cb(streaming_grpc::OK, m_response_msg);
			m_response_msg.Clear();
			m_reader->Read(&m_response_msg, this);

			break;

		default:
			// Shouldn't be possible
			m_state = STATE_CLOSED;
			m_response_cb(streaming_grpc::SHUTDOWN, m_response_msg);

			break;
		}

		return true;
	}

	std::shared_ptr<Stub> m_stub;
	std::unique_ptr<grpc::CompletionQueue> m_cq;
	ResponseMsg m_response_msg;

	// This can be used to pass additional options to the server
	// that control how the RPC should be performed (like add
	// compression, set a deadline for a response, etc). We don't
	// use it.
	std::unique_ptr<grpc::ClientContext> m_ctx;

	std::unique_ptr<grpc::ClientAsyncReader<ResponseMsg>> m_reader;
	response_cb_t m_response_cb;
	State m_state;
};

class coclient
{
public:
	// This function will be called with the response to the rpc.
	typedef std::function<void(bool successful, google::protobuf::Message *response_msg)> response_cb_t;

	coclient(const std::string& install_prefix);
	virtual ~coclient();

	void ping(int64_t token, response_cb_t response_cb);
	void get_swarm_state(response_cb_t response_cb);

	void perform_docker_cmd(sdc_internal::docker_cmd_type cmd,
				const std::string &container_id, response_cb_t response_cb);

	void get_orchestrator_events(sdc_internal::orchestrator_events_stream_command cmd, response_cb_t response_cb);
	void get_orchestrator_event_messages(sdc_internal::orchestrator_attach_user_events_stream_command cmd, response_cb_t response_cb);

	// Read up to m_max_loop_evts from the rpc response queue
	// Returns true unless we drain the queue or detect a shutdown
	bool process_queue();

	static void set_max_loop_evts(const uint32_t max_evts)
	{
		m_max_loop_evts = max_evts;
	}

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

	// Check for any responses and call their callback functions.
	// Returns a number  >= 0 if there are possibly more events to read.
	// Returns the number of events read with this call. If it returns
	// -1 then it suggests no more events to read or some error.
	int32_t next();

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
		std::unique_ptr<grpc::ClientAsyncReader<sdc_internal::array_congroup_update_event>> orchestrator_events_reader;
		std::unique_ptr<grpc::ClientAsyncReader<sdc_internal::k8s_user_event>> orchestrator_event_message_reader;
	};

	std::unique_ptr<sdc_internal::CoInterface::Stub> m_stub;

	grpc::CompletionQueue m_cq;

	google::protobuf::TextFormat::Printer m_print;

	std::string m_domain_sock;
	static std::string default_domain_sock;
	bool m_outstanding_swarm_state;
	static uint32_t m_max_loop_evts;
};
#endif // CYGWING_AGENT
