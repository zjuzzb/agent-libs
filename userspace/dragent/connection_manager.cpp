#include "connection_manager.h"
#include "logger.h"
#include "protocol.h"
#include "draios.pb.h"
#include "utils.h"
#include "watchdog_runnable_fatal_error.h"
#include "Poco/Net/InvalidCertificateHandler.h"
#include "Poco/Net/SSLException.h"

#ifndef TCP_USER_TIMEOUT
// Define it here because old glibc versions do not have this flag (eg, Centos6)
#define TCP_USER_TIMEOUT	 18 /* How long for loss retry before timeout */
#endif

DRAGENT_LOGGER();

const chrono::seconds connection_manager::WORKING_INTERVAL_S(10);
const uint32_t connection_manager::RECONNECT_MIN_INTERVAL_S = 1;
const uint32_t connection_manager::RECONNECT_MAX_INTERVAL_S = 60;

class LoggingCertificateHandler : public Poco::Net::InvalidCertificateHandler
{
public:
	using Poco::Net::InvalidCertificateHandler::InvalidCertificateHandler;

	// Mimicking Poco::Net::ConsoleCertificateHandler but no user input
	virtual void onInvalidCertificate(const void *pSender,
					  Poco::Net::VerificationErrorArgs &errorCert) {
		LOG_ERROR("Certificate verification failed: " +
			     errorCert.errorMessage() + " (" +
			     NumberFormatter::format(errorCert.errorNumber()) + ")" +
			     ", Issuer: " + errorCert.certificate().issuerName() +
			     ", Subject: " + errorCert.certificate().subjectName() +
			     ", chain position " + NumberFormatter::format(errorCert.errorDepth())
			);
	}
};

connection_manager::connection_manager(dragent_configuration* configuration,
				       protocol_queue* queue,
				       sinsp_worker* sinsp_worker,
				       capture_job_handler *capture_job_handler) :
	dragent::watchdog_runnable("connection_manager"),
	m_socket(NULL),
	m_connected(false),
	m_buffer(RECEIVER_BUFSIZE),
	m_buffer_used(0),
	m_configuration(configuration),
	m_queue(queue),
	m_sinsp_worker(sinsp_worker),
	m_capture_job_handler(capture_job_handler),
	m_reconnect_interval(0)
{
	Poco::Net::initializeSSL();
}

connection_manager::~connection_manager()
{
	Poco::Net::uninitializeSSL();
}

bool connection_manager::init()
{
	if(m_configuration->m_server_addr == "" ||
	   m_configuration->m_server_port == 0)
	{
		LOG_WARNING("Server address has not been specified");
		return false;
	}

	if(!m_configuration->m_ssl_enabled)
	{
		return true;
	}

	LOG_INFO("SSL enabled, initializing context");

	Poco::Net::Context::VerificationMode verification_mode;
	SharedPtr<LoggingCertificateHandler> invalid_cert_handler = nullptr;
	std::string cert_dir;

	if(m_configuration->m_ssl_verify_certificate)
	{
		verification_mode = Poco::Net::Context::VERIFY_STRICT;
		invalid_cert_handler = new LoggingCertificateHandler(false);
		if (!m_configuration->m_ssl_ca_cert_dir.empty())
		{
			cert_dir = m_configuration->m_ssl_ca_cert_dir;
		}
		else
		{
			cert_dir = get_openssldir();
		}
		LOG_INFO("SSL CA cert dir: " + cert_dir);
	}
	else
	{
		verification_mode = Poco::Net::Context::VERIFY_NONE;
	}

	Poco::Net::Context::Ptr ptrContext = new Poco::Net::Context(
		Poco::Net::Context::CLIENT_USE,
		"",
		"",
		cert_dir,
		verification_mode,
		9,
		false,
		"ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");

	try
	{
		LOG_INFO("openssl loading cert: "
				   + m_configuration->m_ssl_ca_certificate);
		Poco::Crypto::X509Certificate ca_cert(m_configuration->m_ssl_ca_certificate);
		ptrContext->addCertificateAuthority(ca_cert);
	}
	catch (Poco::Net::SSLException &e)
	{
		// thrown by addCertificateAuthority()
		LOG_ERROR("Unable to add ssl ca certificate: "
			     + e.message());
	}
	catch (Poco::IOException& e)
	{
		// thrown by X509Certificate constructor
		LOG_ERROR("Unable to read ssl ca certificate: "
			     + e.message());
	}
	catch (...)
	{
		LOG_ERROR("Unable to load ssl ca certificate: "
			     + m_configuration->m_ssl_ca_certificate);
	}

	Poco::Net::SSLManager::instance().initializeClient(0, invalid_cert_handler, ptrContext);

	return true;
}

// Find the host's default OPENSSLDIR
// This is best effort for now, so don't log at warn/error
std::string connection_manager::get_openssldir()
{
	std::string path;
	errno = 0;
	FILE *out = popen("openssl version -d 2>&1", "r");
	if (!out)
	{
		LOG_INFO(string("openssl popen() failed: ")
				   + strerror(errno));
		return path;
	}

	// Sample output:
	// $ openssl version -d
	// OPENSSLDIR: "/usr/lib/ssl"
	//
	// It should only be one line, but read multiple lines in case the
	// format changes. Also the while control structure works better
	char buf[256];
	int ii = 0;
	const int max_lines = 10;
	while (ii < max_lines && fgets(buf, sizeof(buf), out))
	{
		ii++;
		std::string out_str(buf);
		LOG_DEBUG("openssl read from popen(): " + out_str);

		// Would use std::regex if we had compiler support
		std::string start_targ("OPENSSLDIR: \"");
		auto start_pos = out_str.find(start_targ);
		if (start_pos == std::string::npos)
		{
			continue;
		}
		start_pos += start_targ.size();
		std::string end_targ("\"");
		auto end_pos = out_str.find(end_targ, start_pos);
		if (end_pos == std::string::npos)
		{
			continue;
		}

		path = out_str.substr(start_pos, end_pos - start_pos)
			+ "/certs";
		LOG_DEBUG("found OPENSSLDIR: " + path);
		break;
	}

	int ret = pclose(out);
	LOG_DEBUG(string("openssl pclose() exit code: ")
		     + std::to_string(WEXITSTATUS(ret)));
	return path;
}

bool connection_manager::connect()
{
#ifndef CYGWING_AGENT
	if (m_configuration->m_promex_enabled)
	{
		const string& url = m_configuration->m_promex_connect_url.empty() ?
			"unix:" + m_configuration->m_root_dir + "/run/promex.sock" :
			m_configuration->m_promex_connect_url;
		m_prom_channel = grpc::CreateChannel(url, grpc::InsecureChannelCredentials());
		m_prom_conn = make_shared<promex_pb::PrometheusExporter::Stub>(m_prom_channel);
	}
#endif
	try
	{
		ASSERT(m_socket.isNull());

		SocketAddress sa(m_configuration->m_server_addr, m_configuration->m_server_port);

		// The following message was provided to Goldman Sachs (Oct 2018). Do not change.
		LOG_INFO("Connecting to collector " + sa.toString());

		if(m_configuration->m_ssl_enabled)
		{
			m_socket = new Poco::Net::SecureStreamSocket();

			((Poco::Net::SecureStreamSocket*) m_socket.get())->setLazyHandshake(true);
			((Poco::Net::SecureStreamSocket*) m_socket.get())->setPeerHostName(m_configuration->m_server_addr);
			((Poco::Net::SecureStreamSocket*) m_socket.get())->connect(sa, SOCKET_TIMEOUT_DURING_CONNECT_US);
		}
		else
		{
			m_socket = new Poco::Net::StreamSocket();
			m_socket->connect(sa, SOCKET_TIMEOUT_DURING_CONNECT_US);
		}

		if(m_configuration->m_ssl_enabled)
		{
			//
			// This is done to prevent getting stuck forever waiting during the handshake
			// if the server doesn't speak to us
			//
			m_socket->setSendTimeout(SOCKET_TIMEOUT_DURING_CONNECT_US);
			m_socket->setReceiveTimeout(SOCKET_TIMEOUT_DURING_CONNECT_US);

			int32_t ret = ((Poco::Net::SecureStreamSocket*) m_socket.get())->completeHandshake();
			if(ret != 1)
			{
				LOG_ERROR("SSL Handshake didn't complete");
				disconnect();
				return false;
			}

			((Poco::Net::SecureStreamSocket*) m_socket.get())->verifyPeerCertificate();

			LOG_INFO("SSL identity verified");
		}

		//
		// Set the send buffer size for the socket
		//
		m_socket->setSendBufferSize(m_configuration->m_transmitbuffer_size);
		m_socket->setSendTimeout(SOCKET_TIMEOUT_AFTER_CONNECT_US);
		m_socket->setReceiveTimeout(SOCKET_TIMEOUT_AFTER_CONNECT_US);
		try
		{
			// This option makes the connection fail earlier in case of unplugged cable
			m_socket->setOption(IPPROTO_TCP, TCP_USER_TIMEOUT, SOCKET_TCP_TIMEOUT_MS);
		}
		catch(std::exception&)
		{
			// ignore if kernel does not support this
			// alternatively, could be a setsockopt() call to avoid exception
		}

		LOG_INFO("Connected to collector");
		m_connected = true;
		return true;
	}
	catch(Poco::IOException& e)
	{
		// The following message was provided to Goldman Sachs (Oct 2018). Do not change.
		LOG_ERROR("connect():IOException: " + e.displayText());
		disconnect();
		return false;
	}
	catch(Poco::TimeoutException& e)
	{
		// The following message was provided to Goldman Sachs (Oct 2018). Do not change.
		LOG_ERROR("connect():Timeout: " + e.displayText());
		disconnect();
		return false;
	}
	return false;
}

void connection_manager::disconnect()
{
	if(chrono::system_clock::now() - m_last_connection_failure >= WORKING_INTERVAL_S)
	{
		m_reconnect_interval = RECONNECT_MIN_INTERVAL_S;
	}
	else
	{
		m_reconnect_interval = std::min(std::max(connection_manager::RECONNECT_MIN_INTERVAL_S, m_reconnect_interval * 2), RECONNECT_MAX_INTERVAL_S);
	}

	if(!m_socket.isNull())
	{
		m_socket->close();
		m_socket = NULL;
		m_connected = false;
		m_buffer_used = 0;
	}
#ifndef CYGWING_AGENT
	m_prom_channel = nullptr;
	m_prom_conn = nullptr;
#endif
}

#ifndef CYGWING_AGENT
bool connection_manager::prometheus_connected()
{
	if (!m_prom_conn)
	{
		return false;
	}

	auto state = m_prom_channel->GetState(true);
	switch (state)
	{
		case GRPC_CHANNEL_IDLE:
		case GRPC_CHANNEL_READY:
			return true;
		default:
			g_logger.format(sinsp_logger::SEV_INFO, "Connection to prometheus exporter in state %d", (int)state);
			return false;
	}

}
#endif

void connection_manager::do_run()
{
	if(!init())
	{
		THROW_DRAGENT_WR_FATAL_ERROR("initialization failed");
	}

	std::shared_ptr<protocol_queue_item> item;

	while(heartbeat())
	{
		//
		// Make sure we have a valid connection
		//
		if(m_socket.isNull())
		{
			LOG_INFO("Waiting to connect %u s", m_reconnect_interval);

			for(uint32_t waited_time = 0; waited_time < m_reconnect_interval; ++waited_time)
			{
				(void)heartbeat();
				Thread::sleep(1000);
			}

			if(dragent_configuration::m_terminate)
			{
				break;
			}

			m_last_connection_failure = chrono::system_clock::now();

			if(!connect())
			{
				continue;
			}
		}

		//
		// Check if we received a message. We do it before so nothing gets lost if ELBs
		// still negotiates a connection and then sends us out at the first read/write
		//
		receive_message();

		if(!item)
		{
			//
			// Wait 300ms to get a message from the queue
			//
			m_queue->get(&item, 300);
		}

		if(item)
		{
			//
			// Got a message, transmit it
			//
			if(transmit_buffer(sinsp_utils::get_current_time_ns(), item))
			{
				item = NULL;
			}
		}
	}
}

bool connection_manager::transmit_buffer(uint64_t now, std::shared_ptr<protocol_queue_item> &item)
{
	// Sometimes now can be less than ts_ns. The timestamp in
	// metrics messages is rounded up to the following metrics
	// interval.

	if (now > item->ts_ns &&
	    (now - item->ts_ns) > 5000000000UL)
	{
		LOG_WARNING("Transmitting delayed message. type=" + to_string(item->message_type)
			       + ", now=" + to_string(now)
			       + ", ts=" + to_string(item->ts_ns)
			       + ", delay_ms=" + to_string((now - item->ts_ns)/ 1000000.0));
	}
#ifndef CYGWING_AGENT
	if (item->message_type == draiosproto::message_type::METRICS && prometheus_connected())
	{
		grpc::ClientContext context;
		auto deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(20);
		context.set_deadline(deadline);

		draiosproto::metrics msg;
		promex_pb::PrometheusExporterResponse response;
		if (parse_protocol_queue_item(*item, &msg))
		{
			// XXX: this is blocking
			m_prom_conn->EmitMetrics(&context, msg, &response);
		}
	}
#endif

	try
	{
		if(m_socket.isNull())
		{
			return false;
		}

		int32_t res = m_socket->sendBytes(item->buffer.data(), item->buffer.size());
		if(res == Poco::Net::SecureStreamSocket::ERR_SSL_WANT_READ ||
			res == Poco::Net::SecureStreamSocket::ERR_SSL_WANT_WRITE)
		{
			return false;
		}

		if(res != (int32_t) item->buffer.size())
		{
			LOG_ERROR("sendBytes sent just "
				+ NumberFormatter::format(res)
				+ ", expected " + NumberFormatter::format(item->buffer.size()));

			disconnect();

			ASSERT(false);
			return false;
		}

		// The following message was provided to Goldman Sachs (Oct 2018). Do not change.
		LOG_INFO("Sent msgtype="
				   + to_string((int) item->message_type)
				   + " len="
				   + Poco::NumberFormatter::format(item->buffer.size()) + " to collector");

		return true;
	}
	catch(Poco::IOException& e)
	{
		// When the output buffer gets full sendBytes() results in
		// a TimeoutException for SSL connections and EWOULDBLOCK for non-SSL
		// connections, so we'll treat them the same.
		if ((e.code() == POCO_EWOULDBLOCK) || (e.code() == POCO_EAGAIN))
		{
			// We shouldn't risk hanging indefinitely if the EWOULDBLOCK is
			// caused by an attempted send larger than the buffer size
			if (item->buffer.size() > m_configuration->m_transmitbuffer_size)
			{
				LOG_ERROR("transmit larger than bufsize failed ("
					+ NumberFormatter::format(item->buffer.size()) + ">" +
					NumberFormatter::format(m_configuration->m_transmitbuffer_size)
					 + "): " + e.displayText());
				disconnect();
			}
			else
			{
				LOG_DEBUG("transmit: Ignoring: " + e.displayText());
			}
		}
		else
		{
			LOG_ERROR("transmit:IOException: " + e.displayText());
			disconnect();
		}
	}
	catch(Poco::TimeoutException& e)
	{
		LOG_DEBUG("transmit:Timeout: " + e.displayText());
	}

	return false;
}

void connection_manager::receive_message()
{
	try
	{
		if(m_socket.isNull())
		{
			return;
		}

		// If the socket has nothing readable, return
		// immediately. This ensures that when the queue has
		// multiple items queued we don't limit the rate at
		// which we dequeue and send messages.
		if (!m_socket->poll(Poco::Timespan(), Poco::Net::Socket::SELECT_READ))
		{
			return;
		}

		if(m_buffer_used == 0)
		{
			// We begin by reading and processing the protocol header
			int32_t res = m_socket->receiveBytes(m_buffer.begin(), sizeof(dragent_protocol_header), MSG_WAITALL);
			if(res == Poco::Net::SecureStreamSocket::ERR_SSL_WANT_READ ||
			   res == Poco::Net::SecureStreamSocket::ERR_SSL_WANT_WRITE)
			{
				return;
			}

			if(res == 0)
			{
				LOG_ERROR("Lost connection (reading header)");
				disconnect();
				return;
			}

			// TODO: clean up buffering of received data. Remains of protocol
			// header might come in the next recv().
			if(res != sizeof(dragent_protocol_header))
			{
				LOG_ERROR("Protocol error: couldn't read full header: " + NumberFormatter::format(res));
				ASSERT(false);
				disconnect();
				return;
			}

			dragent_protocol_header* header = (dragent_protocol_header*) m_buffer.begin();
			header->len = ntohl(header->len);

			if((header->len < sizeof(dragent_protocol_header)) ||
				(header->len > MAX_RECEIVER_BUFSIZE))
			{
				LOG_ERROR("Protocol error: invalid header length " + NumberFormatter::format(header->len));
				ASSERT(false);
				disconnect();
				return;
			}

			if(header->len > m_buffer.size())
			{
				m_buffer.resize(header->len);
			}

			m_buffer_used = sizeof(dragent_protocol_header);
		}

		// Then we read the actual message, it may arrive in
		// several chunks, in this case the function will be called
		// at the next loop cycle and will continue reading
		auto header = (dragent_protocol_header*) m_buffer.begin();
		auto res = m_socket->receiveBytes(
				m_buffer.begin() + m_buffer_used,
				header->len - m_buffer_used,
				MSG_WAITALL);

		if(res == Poco::Net::SecureStreamSocket::ERR_SSL_WANT_READ ||
			res == Poco::Net::SecureStreamSocket::ERR_SSL_WANT_WRITE)
		{
			return;
		}

		if(res == 0)
		{
			LOG_ERROR("Lost connection (reading message)");
			disconnect();
			ASSERT(false);
			return;
		}

		if(res < 0)
		{
			LOG_ERROR("Connection error while reading: " +
				NumberFormatter::format(res));
			disconnect();
			ASSERT(false);
			return;
		}

		m_buffer_used += res;
		LOG_DEBUG("Receiving message version=" + NumberFormatter::format(header->version) +
					 " len=" + NumberFormatter::format(header->len) + " messagetype=" + NumberFormatter::format(header->messagetype) +
					" received=" + NumberFormatter::format(m_buffer_used));

		if(m_buffer_used == header->len)
		{
			m_buffer_used = 0;

			if(header->version != dragent_protocol::PROTOCOL_VERSION_NUMBER)
			{
				LOG_ERROR("Received command for incompatible version protocol "
							 + NumberFormatter::format(header->version));
				ASSERT(false);
				return;
			}

			// When the message is complete, process it
			// and reset the buffer
			LOG_INFO("Received command "
							   + NumberFormatter::format(header->messagetype)
							   + " (" + draiosproto::message_type_Name((draiosproto::message_type) header->messagetype) + ")");

			switch(header->messagetype)
			{
			case draiosproto::message_type::DUMP_REQUEST_START:
				handle_dump_request_start(
						m_buffer.begin() + sizeof(dragent_protocol_header),
						header->len - sizeof(dragent_protocol_header));
				break;
			case draiosproto::message_type::DUMP_REQUEST_STOP:
				handle_dump_request_stop(
						m_buffer.begin() + sizeof(dragent_protocol_header),
						header->len - sizeof(dragent_protocol_header));
				break;
			case draiosproto::message_type::CONFIG_DATA:
				handle_config_data(
						m_buffer.begin() + sizeof(dragent_protocol_header),
						header->len - sizeof(dragent_protocol_header));
				break;
			case draiosproto::message_type::ERROR_MESSAGE:
				handle_error_message(
					m_buffer.begin() + sizeof(dragent_protocol_header),
					header->len - sizeof(dragent_protocol_header));
				break;
#ifndef CYGWING_AGENT
			case draiosproto::message_type::POLICIES:
				handle_policies_message(
					m_buffer.begin() + sizeof(dragent_protocol_header),
					header->len - sizeof(dragent_protocol_header));
				break;
			case draiosproto::message_type::COMP_CALENDAR:
				handle_compliance_calendar_message(
					m_buffer.begin() + sizeof(dragent_protocol_header),
					header->len - sizeof(dragent_protocol_header));
				break;
			case draiosproto::message_type::ORCHESTRATOR_EVENTS:
				handle_orchestrator_events(
					m_buffer.begin() + sizeof(dragent_protocol_header),
					header->len - sizeof(dragent_protocol_header));
				break;
			case draiosproto::message_type::BASELINES:
				handle_baselines_message(
					m_buffer.begin() + sizeof(dragent_protocol_header),
					header->len - sizeof(dragent_protocol_header));
				break;
#endif
			default:
				LOG_ERROR("Unknown message type: "
							 + NumberFormatter::format(header->messagetype));
				ASSERT(false);
			}
		}

		if(m_buffer_used > header->len)
		{
			LOG_ERROR("Protocol out of sync, disconnecting");
			disconnect();
			ASSERT(false);
			return;
		}
	}
	catch(Poco::IOException& e)
	{
		LOG_ERROR("receive:IOException: " + e.displayText());
		disconnect();
	}
	catch(Poco::TimeoutException& e)
	{
		LOG_DEBUG("receive:Timeout: " + e.displayText());
	}
}

void connection_manager::handle_dump_request_start(uint8_t* buf, uint32_t size)
{
	draiosproto::dump_request_start request;
	if(!dragent_protocol::buffer_to_protobuf(buf, size, &request))
	{
		return;
	}

	std::shared_ptr<capture_job_handler::dump_job_request> job_request =
		make_shared<capture_job_handler::dump_job_request>();

	job_request->m_start_details = make_unique<capture_job_handler::start_job_details>();

	job_request->m_request_type = capture_job_handler::dump_job_request::JOB_START;
	job_request->m_token = request.token();

	if(request.has_filters())
	{
		job_request->m_start_details->m_filter = request.filters();
	}

	if(request.has_duration_ns())
	{
		job_request->m_start_details->m_duration_ns = request.duration_ns();
	}

	if(request.has_max_size())
	{
		job_request->m_start_details->m_max_size = request.max_size();
	}

	if(request.has_past_duration_ns())
	{
		job_request->m_start_details->m_past_duration_ns = request.past_duration_ns();
	}

	if(request.has_past_size())
	{
		job_request->m_start_details->m_past_size = request.past_size();
	}

	// Note: sending request via sinsp_worker so it can add on
	// needed state (e.g. sinsp_dumper)
	m_sinsp_worker->queue_job_request(job_request);
}

void connection_manager::handle_dump_request_stop(uint8_t* buf, uint32_t size)
{
	draiosproto::dump_request_stop request;
	if(!dragent_protocol::buffer_to_protobuf(buf, size, &request))
	{
		return;
	}

	std::shared_ptr<capture_job_handler::dump_job_request> job_request =
		make_shared<capture_job_handler::dump_job_request>();

	job_request->m_stop_details = make_unique<capture_job_handler::stop_job_details>();

	job_request->m_request_type = capture_job_handler::dump_job_request::JOB_STOP;
	job_request->m_token = request.token();

	// For captures created by the connection manager,
	// m_defer_send is never true, so there isn't any need to
	// worry about stopping a deferred capture. But set this for
	// completeness.
	job_request->m_stop_details->m_remove_unsent_job = false;

	// This could go directly to the capture handler as there's no
	// need to add any state when stopping a job. However, still
	// sending it via the sinsp_worker so there's no chance of the
	// stop message arriving at the capture handler before the
	// start. (Unlikely, but just being safe).
	m_sinsp_worker->queue_job_request(job_request);
}

void connection_manager::handle_config_data(uint8_t* buf, uint32_t size)
{
	if(m_configuration->m_auto_config)
	{
		draiosproto::config_data request;
		if(!dragent_protocol::buffer_to_protobuf(buf, size, &request))
		{
			return;
		}
		for(const auto& config_file_proto : request.config_files())
		{
			std::string errstr;

			if(m_configuration->save_auto_config(config_file_proto.name(),
							     config_file_proto.content(),
							     errstr) < 0)
			{
				LOG_ERROR(errstr);
			}
		}
	}
	else
	{
		LOG_DEBUG("Auto config disabled, ignoring CONFIG_DATA message");
	}
}

void connection_manager::handle_error_message(uint8_t* buf, uint32_t size) const
{
	draiosproto::error_message err_msg;
	if(!dragent_protocol::buffer_to_protobuf(buf, size, &err_msg))
	{
		LOG_ERROR("received unparsable error message");
		return;
	}

	string err_str = "unknown error";
	bool term = false;

	// Log as much useful info as possible from the error_message
	if(err_msg.has_type())
	{
		const draiosproto::error_type err_type = err_msg.type();
		if (draiosproto::error_type_IsValid(err_type)) {
			err_str = draiosproto::error_type_Name(err_type);

			if(err_msg.has_description() && !err_msg.description().empty())
			{
				err_str += " (" + err_msg.description() + ")";
			}

			if(err_type == draiosproto::error_type::ERR_INVALID_CUSTOMER_KEY ||
			   err_type == draiosproto::error_type::ERR_PROTO_MISMATCH)
			{
				term = true;
				err_str += ", terminating the agent";
			}
		}
		else
		{
			err_str = ": received invalid error type: " + std::to_string(err_type);
		}
	}

	LOG_ERROR("received " + err_str);

	if(term)
	{
		dragent_configuration::m_terminate = true;
	}
}

#ifndef CYGWING_AGENT
void connection_manager::handle_policies_message(uint8_t* buf, uint32_t size)
{
	draiosproto::policies policies;
	string errstr;

	if(!m_configuration->m_security_enabled)
	{
		LOG_DEBUG("Security disabled, ignoring POLICIES message");
		return;
	}

	if(m_configuration->m_security_policies_file != "")
	{
		LOG_INFO("Security policies file configured in dragent.yaml, ignoring POLICIES message");
		return;
	}

	if(!dragent_protocol::buffer_to_protobuf(buf, size, &policies))
	{
		LOG_ERROR("Could not parse policies message");
		return;
	}

	if (!m_sinsp_worker->load_policies(policies, errstr))
	{
		LOG_ERROR("Could not load policies message: " + errstr);
		return;
	}
}

void connection_manager::handle_compliance_calendar_message(uint8_t* buf, uint32_t size)
{
	draiosproto::comp_calendar calendar;
	string errstr;

	if(!m_configuration->m_security_enabled)
	{
		LOG_DEBUG("Security disabled, ignoring COMP_CALENDAR message");
		return;
	}

	if(m_configuration->m_security_compliance_schedule != "")
	{
		LOG_INFO("Security compliance schedule configured in dragent.yaml, ignoring COMP_CALENDAR message");
		return;
	}

	if(!dragent_protocol::buffer_to_protobuf(buf, size, &calendar))
	{
		LOG_ERROR("Could not parse comp_calendar message");
		return;
	}

	if (!m_sinsp_worker->set_compliance_calendar(calendar, errstr))
	{
		LOG_ERROR("Could not set compliance calendar: " + errstr);
		return;
	}
}
#endif

#ifndef CYGWING_AGENT
void connection_manager::handle_orchestrator_events(uint8_t* buf, uint32_t size)
{
	draiosproto::orchestrator_events evts;

	if(!m_configuration->m_security_enabled)
	{
		LOG_DEBUG("Security disabled, ignoring ORCHESTRATOR_EVENTS message");
		return;
	}

	if(!dragent_protocol::buffer_to_protobuf(buf, size, &evts))
	{
		LOG_ERROR("Could not parse orchestrator_events message");
		return;
	}

	m_sinsp_worker->receive_hosts_metadata(evts);
}
#endif

#ifndef CYGWING_AGENT
void connection_manager::handle_baselines_message(uint8_t* buf, uint32_t size)
{
	draiosproto::baselines baselines;
	string errstr;

	if(!m_configuration->m_security_enabled)
	{
		LOG_DEBUG("Security disabled, ignoring BASELINES message");
		return;
	}

	if(m_configuration->m_security_baselines_file != "")
	{
		LOG_INFO("Security baselines file configured in dragent.yaml, ignoring BASELINES message");
		return;
	}

	if(!dragent_protocol::buffer_to_protobuf(buf, size, &baselines))
	{
		LOG_ERROR("Could not parse baselines message");
		return;
	}

	if (!m_sinsp_worker->load_baselines(baselines, errstr))
	{
		LOG_ERROR("Could not load baselines message: " + errstr);
		return;
	}
}
#endif
