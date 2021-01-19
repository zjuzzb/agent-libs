#pragma once

#include "common_logger.h"
#include "configuration.h"
#include "connection_manager.h"
#include "error_handler.h"
#include "main.h"
#include "protocol_handler.h"
#include "subprocesses_logger.h"
#include "watchdog.h"
#include "watchdog_runnable_pool.h"

namespace draiosproto
{
class agentino_metadata;
}

///////////////////////////////////////////////////////////////////////////////
// The main application class
///////////////////////////////////////////////////////////////////////////////
class agentino_app : public Poco::Util::ServerApplication
{
public:
	agentino_app();
	~agentino_app();

protected:
	void initialize(Application& self) override;
	void uninitialize() override;
	void defineOptions(OptionSet& options) override;
	void handleOption(const std::string& name, const std::string& value) override;
	int main(const std::vector<std::string>& args);

private:
	int sdagent_main();
	inline bool timeout_expired(int64_t last_activity_age_ns,
	                            uint64_t timeout_s,
	                            const char* label,
	                            const char* tail);
	void watchdog_check(uint64_t uptime_s);
	void dump_heap_profile(uint64_t uptime_s, bool throttle = true);
	void initialize_logging();
	Logger* make_console_channel(AutoPtr<Formatter> formatter);
	void setup_coredumps();

	void build_metadata_message(draiosproto::agentino_metadata& msg);

	dragent_configuration m_configuration;
	dragent_error_handler m_error_handler;
	flush_queue m_serializer_queue;
	/// Queue consumed by connection_manager for transmission to backend
	protocol_queue m_transmit_queue;

	protocol_handler m_protocol_handler;

	log_reporter m_log_reporter;
	subprocesses_logger m_subprocesses_logger;

	watchdog_runnable_pool m_pool;

	// indicates whether we're talking directly to the BE, bypassing agentone
	bool m_direct;

	std::string m_hostname;
	std::string m_container_name;
	std::string m_container_image;
	std::string m_container_id;
	std::map<std::string, std::string> m_metadata;
};
