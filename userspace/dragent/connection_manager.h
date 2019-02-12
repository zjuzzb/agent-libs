#pragma once

#include <chrono>
#include <memory>
#include "blocking_queue.h"
#include "capture_job_handler.h"
#include "sinsp_worker.h"
#include "watchdog_runnable.h"

#ifndef CYGWING_AGENT
#include "promex.pb.h"
#include "promex.grpc.pb.h"
#endif

class dragent_configuration;
class sinsp_worker;

class connection_manager : public dragent::watchdog_runnable
{
public:
	connection_manager(dragent_configuration* configuration,
			   protocol_queue* queue,
			   sinsp_worker* sinsp_worker,
			   capture_job_handler *capture_job_handler);
	~connection_manager();

	bool is_connected() const
	{
		return m_connected && !m_socket.isNull();
	}

	static const uint32_t SOCKET_TIMEOUT_DURING_CONNECT_US = 60 * 1000 * 1000;
	static const uint32_t SOCKET_TIMEOUT_AFTER_CONNECT_US = 100 * 1000;

private:
	bool init();
	void do_run() override;
	static std::string get_openssldir();
	bool connect();
	void disconnect();
	void disconnect(SharedPtr<StreamSocket> ssp);
	bool transmit_buffer(uint64_t now, std::shared_ptr<protocol_queue_item> &item);
	bool receive_message();
	void handle_dump_request_start(uint8_t* buf, uint32_t size);
	void handle_dump_request_stop(uint8_t* buf, uint32_t size);
	void handle_config_data(uint8_t* buf, uint32_t size);
	void handle_error_message(uint8_t* buf, uint32_t size) const;
#ifndef CYGWING_AGENT
	void handle_policies_message(uint8_t* buf, uint32_t size);
	void handle_compliance_calendar_message(uint8_t* buf, uint32_t size);
	void handle_orchestrator_events(uint8_t* buf, uint32_t size);
	void handle_baselines_message(uint8_t* buf, uint32_t size);
	bool prometheus_connected() const;
#endif
	static const uint32_t MAX_RECEIVER_BUFSIZE = 1 * 1024 * 1024; // 1MiB
	static const uint32_t RECEIVER_BUFSIZE = 32 * 1024;
	static const uint32_t RECONNECT_MIN_INTERVAL_S;
	static const uint32_t RECONNECT_MAX_INTERVAL_S;
	static const unsigned int SOCKET_TCP_TIMEOUT_MS = 60 * 1000;
	static const chrono::seconds WORKING_INTERVAL_S;

	SharedPtr<StreamSocket> m_socket;
	bool m_connected;
	Buffer<uint8_t> m_buffer;
	uint32_t m_buffer_used;
	dragent_configuration* m_configuration;
	protocol_queue* m_queue;
	sinsp_worker* m_sinsp_worker;
	capture_job_handler *m_capture_job_handler;

	uint32_t m_reconnect_interval;
	chrono::time_point<std::chrono::system_clock> m_last_connection_failure;

#ifndef CYGWING_AGENT
	// communication with Prometheus exporter
	std::shared_ptr<promex_pb::PrometheusExporter::Stub> m_prom_conn;
	std::shared_ptr<grpc::Channel> m_prom_channel;
#endif
};
