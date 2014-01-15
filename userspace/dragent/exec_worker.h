#pragma once

#include "main.h"
#include "protocol.h"
#include "draios.pb.h"
#include "configuration.h"

class exec_worker : public Runnable
{
public:
	exec_worker(dragent_configuration* configuration, protocol_queue* queue, 
		const string& token, const string& command_line);

	void run();

private:
	void send_error(const string& error);
	void prepare_response(draiosproto::exec_cmd_response* response);
	void queue_response(const draiosproto::exec_cmd_response& response);
	void read_from_pipe(Pipe* pipe, string* output);

	static const string m_name;

	dragent_configuration* m_configuration;
	protocol_queue* m_queue;
	string m_token;
	string m_command_line;
};
