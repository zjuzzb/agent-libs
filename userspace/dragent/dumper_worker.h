#pragma once

#include "draios.pb.h"

#include "main.h"
#include "blocking_queue.h"
#include "configuration.h"
#include "protocol.h"
#include "connection_manager.h"

class dumper_worker : public Runnable
{
public:
	dumper_worker(dragent_queue* queue, dragent_configuration* configuration, 
		uint64_t duration_ns, const string& filter);
	
	void run();

private:
	void prepare_response(draiosproto::dump_response* response);
	void queue_response(const draiosproto::dump_response& response);
	void send_file();
	std::streamsize copy_file(FileInputStream* istr, std::string* str);

	static const string m_name;

	dragent_queue* m_queue;
	dragent_configuration* m_configuration;
	uint64_t m_duration_ms;
	string m_filter;
};
