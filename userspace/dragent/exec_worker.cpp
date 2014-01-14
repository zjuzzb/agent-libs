#include "exec_worker.h"

const string exec_worker::m_name = "exec_worker";

exec_worker::exec_worker(dragent_configuration* configuration, protocol_queue* queue,
		const string& token, const string& command_line):
	
	m_configuration(configuration),
	m_queue(queue),
	m_token(token),
	m_command_line(command_line)
{
}

void exec_worker::run()
{
	//
	// A quick hack to automatically delete this object
	//
	SharedPtr<exec_worker> ptr(this);

	g_log->information(m_name + ": Starting");	
	g_log->information(m_name + ": Running command '" + m_command_line + "', token " + m_token);

	vector<string> args;
	Pipe out_pipe;
	Pipe err_pipe;
	ProcessHandle process = Process::launch(m_command_line, args, NULL, &out_pipe, &err_pipe);
	int exit_code = process.wait();

	PipeInputStream out_istr(out_pipe);
	string std_out;
	int c = out_istr.get();
	while(c != -1) 
	{
		std_out += (char) c;
		c = out_istr.get();
	}

	PipeInputStream err_istr(err_pipe);
	string std_err;
	c = err_istr.get();
	while(c != -1) 
	{
		std_err += (char) c;
		c = err_istr.get();
	}

	printf("exit %d std_out '%s' std_err '%s'\n", exit_code, std_out.c_str(), std_err.c_str());

	draiosproto::exec_cmd_response response;
	prepare_response(&response);
	response.set_exit_val(exit_code);
	response.set_std_out(std_out);
	response.set_std_err(std_err);
	queue_response(response);

// 	int64_t sleep_time_ms = m_duration_ms;
// 	while(sleep_time_ms > 0 && !dragent_configuration::m_terminate)
// 	{
// 		Thread::sleep(100);
// 		sleep_time_ms -= 100;
// 	}

// 	if(!dragent_configuration::m_terminate)
// 	{
// 		dragent_configuration::m_dump_enabled = false;
	
// 		if(m_configuration->m_dump_completed.tryWait(60000))
// 		{
// 			g_log->information(m_name + ": Capture completed, sending file");
// 			send_file();
// 		}
// 		else
// 		{
// 			string error = "Timeout waiting for capture completed event";
// 			send_error(error);
// 		}

	g_log->information(m_name + ": Terminating");
}

void exec_worker::send_error(const string& error)
{
	g_log->error(error);
	draiosproto::exec_cmd_response response;
	prepare_response(&response);
	response.set_std_err(error);
	queue_response(response);
}

void exec_worker::prepare_response(draiosproto::exec_cmd_response* response)
{
	response->set_timestamp_ns(dragent_configuration::get_current_time_ns());
	response->set_customer_id(m_configuration->m_customer_id);
	response->set_machine_id(m_configuration->m_machine_id);
	response->set_token(m_token);
}

void exec_worker::queue_response(const draiosproto::exec_cmd_response& response)
{
	SharedPtr<protocol_queue_item> buffer = dragent_protocol::message_to_buffer(
		dragent_protocol::PROTOCOL_MESSAGE_TYPE_EXEC_COMMAND_RESPONSE, 
		response, 
		m_configuration->m_compression_enabled);

	if(buffer.isNull())
	{
		g_log->error("NULL converting message to buffer");
		return;
	}

	while(!m_queue->put(buffer))
	{
		g_log->error(m_name + ": Queue full, waiting");
		Thread::sleep(1000);

		if(dragent_configuration::m_terminate)
		{
			break;
		}
	}
}
