#include <Poco/File.h>

// From sysdig, for g_logger
#include "sinsp.h"
#include "sinsp_int.h"
#include "logger.h"

#include "analyzer_utils.h"
#include "coclient.h"

using namespace std;

std::string coclient::m_domain_sock = string("/opt/draios/run/cointerface.sock");

coclient::coclient()
{
	m_print.SetSingleLineMode(true);
}

coclient::~coclient()
{
}

void coclient::connect()
{
	m_stub = sdc_internal::CoInterface::NewStub(grpc::CreateChannel(string("unix:") + m_domain_sock,
								grpc::InsecureChannelCredentials()));
}

void coclient::prepare(google::protobuf::Message *request_msg,
		       sdc_internal::cointerface_message_type msg_type,
		       response_cb_t response_cb)
{
	if(!m_stub)
	{
		connect();
	}

	string tmp;
	m_print.PrintToString(*request_msg, &tmp);
	g_logger.log("Sending message to cointerface: " + tmp, sinsp_logger::SEV_DEBUG);

	call_context *call = new call_context();

	call->response_cb = response_cb;

	// Perform the (async) rpc
	// This only works because we only have a single rpc function
	// for a given request message type.
	switch(msg_type) {
		sdc_internal::ping *ping;
		sdc_internal::swarm_state_command *sscmd;

	case sdc_internal::PING:
		// Start the rpc call and have the pong reader read the response when
		// it's ready.
		ping = static_cast<sdc_internal::ping *>(request_msg);
		call->pong_reader = m_stub->AsyncPerformPing(&call->ctx, *ping, &m_cq);

		// Tell the pong reader to write the response into the
		// response message, update status with whether or not the
		// rpc could be performed, and tag the rpc with a tag
		// that is the address of the call struct.
		call->response_msg = make_unique<sdc_internal::pong>();
		call->pong_reader->Finish(static_cast<sdc_internal::pong *>(call->response_msg.get()), &call->status, (void*)call);
		break;

	case sdc_internal::SWARM_STATE_COMMAND:
		// Start the rpc call and have the reader read the response when
		// it's ready.
		sscmd = static_cast<sdc_internal::swarm_state_command *>(request_msg);
		call->swarm_state_reader = m_stub->AsyncPerformSwarmState(&call->ctx, *sscmd, &m_cq);

		// Tell the swarm_state reader to write the response into the
		// response message, update status with whether or not the
		// rpc could be performed, and tag the rpc with a tag
		// that is the address of the call struct.
		call->response_msg = make_unique<sdc_internal::swarm_state_result>();
		call->swarm_state_reader->Finish(static_cast<sdc_internal::swarm_state_result *>(call->response_msg.get()), &call->status, (void*)call);
		break;

	default:
		g_logger.log("Unknown message type " + to_string(msg_type), sinsp_logger::SEV_ERROR);
		break;
	}
}

void coclient::next()
{
	void *tag;
	bool updates_ok;
	grpc::CompletionQueue::NextStatus status;

	status = m_cq.AsyncNext(&tag, &updates_ok, std::chrono::system_clock::now() + std::chrono::milliseconds(10));

	if(status == grpc::CompletionQueue::SHUTDOWN)
	{
		g_logger.log("cointerface process shut down, disconnecting", sinsp_logger::SEV_ERROR);
		m_stub = NULL;
		return;
	}
	else if(status == grpc::CompletionQueue::TIMEOUT)
	{
		return;
	}

	call_context *call = static_cast<call_context *>(tag);

	if(!updates_ok) {
		g_logger.log("cointerface RPC could not be scheduled successfully", sinsp_logger::SEV_ERROR);
		m_stub = NULL;
		return;
	}

	if(call->status.ok()) {
		string tmp;
		m_print.PrintToString(*(call->response_msg), &tmp);

		g_logger.log("Got response from cointerface: " + tmp, sinsp_logger::SEV_DEBUG);

	} else {
		g_logger.log("cointerface rpc failed", sinsp_logger::SEV_DEBUG);
	}

	call->response_cb(call->status.ok(), call->response_msg.get());

	delete call;
}

void coclient::cleanup()
{
	Poco::File f(m_domain_sock);
	if(f.exists())
	{
		f.remove();
	}
}

void coclient::ping(int64_t token, response_cb_t response_cb)
{
	sdc_internal::ping ping;

	ping.set_token(token);

	prepare(&ping, sdc_internal::PING, response_cb);
}
