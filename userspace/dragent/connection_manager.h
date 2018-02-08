#pragma once

#include <memory>

#include "main.h"
#include "configuration.h"
#include "blocking_queue.h"
#include "sinsp_worker.h"
#include "capture_job_handler.h"
#include <chrono>

class connection_manager : public Runnable
{
public:
	connection_manager(dragent_configuration* configuration,
			   protocol_queue* queue,
			   sinsp_worker* sinsp_worker,
			   capture_job_handler *capture_job_handler);
	~connection_manager();

	void run();
	uint64_t get_last_loop_ns()
	{
		return m_last_loop_ns;
	}

	pthread_t get_pthread_id()
	{
		return m_pthread_id;
	}

	bool is_connected()
	{
		return m_connected;
	}

private:
	bool init();
	bool connect();
	void disconnect();
	bool transmit_buffer(uint64_t now, std::shared_ptr<protocol_queue_item> &item);
	void receive_message();
	void handle_dump_request_start(uint8_t* buf, uint32_t size);
	void handle_dump_request_stop(uint8_t* buf, uint32_t size);
	void handle_auto_update();
	void handle_config_data(uint8_t* buf, uint32_t size);
	void handle_error_message(uint8_t* buf, uint32_t size) const;
	void handle_policies_message(uint8_t* buf, uint32_t size);
	void handle_orchestrator_events(uint8_t* buf, uint32_t size);
	void handle_baselines_message(uint8_t* buf, uint32_t size);
	void send_policy_events_messages(uint64_t ts_ns);
	static const uint32_t MAX_RECEIVER_BUFSIZE = 1 * 1024 * 1024; // 1MiB
	static const uint32_t RECEIVER_BUFSIZE = 32 * 1024;
	static const uint32_t SOCKET_TIMEOUT_DURING_CONNECT_US = 60 * 1000 * 1000;
	static const uint32_t SOCKET_TIMEOUT_AFTER_CONNECT_US = 100 * 1000;
	static const uint32_t RECONNECT_MIN_INTERVAL_S;
	static const uint32_t RECONNECT_MAX_INTERVAL_S;
	static const unsigned int SOCKET_TCP_TIMEOUT_MS = 60 * 1000;
	static const chrono::seconds WORKING_INTERVAL_S;
	static const string m_name;

	SharedPtr<StreamSocket> m_socket;
	bool m_connected;
	Buffer<uint8_t> m_buffer;
	uint32_t m_buffer_used;
	dragent_configuration* m_configuration;
	protocol_queue* m_queue;
	sinsp_worker* m_sinsp_worker;
	capture_job_handler *m_capture_job_handler;
	std::atomic<uint64_t> m_last_loop_ns;
	std::atomic<pthread_t> m_pthread_id;

	uint32_t m_reconnect_interval;
	chrono::time_point<std::chrono::system_clock> m_last_connection_failure;
};
