#include "ssh_worker.h"

#include <sys/types.h>
#include <sys/wait.h>

const string ssh_worker::m_name = "ssh_worker";

Mutex ssh_worker::m_sessions_lock;
map<string, ssh_session> ssh_worker::m_sessions;

ssh_worker::ssh_worker(dragent_configuration* configuration, protocol_queue* queue,
		const string& token, const ssh_settings& settings):
	
	m_configuration(configuration),
	m_queue(queue),
	m_token(token),
	m_ssh_settings(settings)
{
}

ssh_worker::~ssh_worker()
{
	Poco::Mutex::ScopedLock lock(m_sessions_lock);

	g_log->information("Erasing session " + m_token);

	m_sessions.erase(m_token);
}

void ssh_worker::run()
{
	//
	// A quick hack to automatically delete this object
	//
	SharedPtr<ssh_worker> ptr(this);

	g_log->information(m_name + ": Opening SSH session, token " + m_token);

	string command = "ssh";
	vector<string> args;

	if(m_ssh_settings.m_port)
	{
		args.push_back("-p");
		args.push_back(NumberFormatter::format(m_ssh_settings.m_port));
	}

	if(!m_ssh_settings.m_key.empty())
	{
		Poco::TemporaryFile file;
		bool created = false;

		try
		{
			created = file.createFile();
		}
		catch(Poco::Exception& e)
		{
		}

		if(!created)
		{
			send_error("Cannot create temporary file for SSH key");
			return;
		}

		g_log->information("Temporary saving key to ");

		ofstream key_file;
		key_file.open(file.path());
		key_file << m_ssh_settings.m_key;
		key_file.close();

		args.push_back("-i");
		args.push_back(file.path());
	}

	if(m_ssh_settings.m_user.empty())
	{
		send_error("User not specified");
		return;
	}

	args.push_back(m_ssh_settings.m_user + "@localhost");

	Pipe in_pipe;
	Pipe out_pipe;
	Pipe err_pipe;

	if(fcntl(in_pipe.writeHandle(), F_SETFL, O_NONBLOCK) == -1)
	{
		send_error("Error setting non blocking mode on in_pipe");
		return;
	}

	if(fcntl(out_pipe.readHandle(), F_SETFL, O_NONBLOCK) == -1)
	{
		send_error("Error setting non blocking mode on out_pipe");
		return;
	}

	if(fcntl(err_pipe.readHandle(), F_SETFL, O_NONBLOCK) == -1)
	{
		send_error("Error setting non blocking mode on err_pipe");
		return;
	}

	ProcessHandle process = Process::launch(command, args, &in_pipe, &out_pipe, &err_pipe);

	ProcessHandle::PID pid = process.id();

	while(!dragent_configuration::m_terminate)
	{
		int status;
		pid_t res = waitpid(pid, &status, WNOHANG);

		if(res == -1)
		{
			send_error("Error waiting for process termination");
			break;
		}

		if(res == 0)
		{
			//
			// Process not terminated, check the outputs and the inputs
			//
			string std_in = get_input(m_token);
			write_to_pipe(&in_pipe, std_in);
			string std_out;
			read_from_pipe(&out_pipe, &std_out);
			string std_err;
			read_from_pipe(&err_pipe, &std_err);

			if(std_out.size() || std_err.size())
			{
				//
				// Report the partial output
				//
				draiosproto::ssh_data response;
				prepare_response(&response);

				if(std_out.size())
				{
					response.set_data(std_out);
				}

		// 		if(std_err.size())
		// 		{
		// 			response.set_std_err(std_err);
		// 		}

				g_log->information("Process not terminated, sending partial std_out (" 
					+ NumberFormatter::format(std_out.size()) + "), std_err (" 
					+ NumberFormatter::format(std_err.size()) + ")");

				queue_response(response);
			}

			Thread::sleep(100);
			continue;
		}

		g_log->information("SSH session terminated");

		string std_out;
		read_from_pipe(&out_pipe, &std_out);
		string std_err;
		read_from_pipe(&err_pipe, &std_err);

		draiosproto::ssh_data response;
		prepare_response(&response);

		if(std_out.size())
		{
			response.set_data(std_out);
		}

		// if(std_err.size())
		// {
		// 	response.set_std_err(std_err);
		// }

		// response.set_exit_val(WEXITSTATUS(status));

		// queue_response(response);

		break;
	}

	g_log->information(m_name + ": Terminating");
}

void ssh_worker::send_error(const string& error)
{
	g_log->error(error);
	draiosproto::ssh_data response;
	prepare_response(&response);
	response.set_error(error);
	queue_response(response);
}

void ssh_worker::prepare_response(draiosproto::ssh_data* response)
{
	response->set_timestamp_ns(dragent_configuration::get_current_time_ns());
	response->set_customer_id(m_configuration->m_customer_id);
	response->set_machine_id(m_configuration->m_machine_id);
	response->set_token(m_token);
}

void ssh_worker::queue_response(const draiosproto::ssh_data& response)
{
	SharedPtr<protocol_queue_item> buffer = dragent_protocol::message_to_buffer(
		draiosproto::message_type::SSH_DATA, 
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

void ssh_worker::read_from_pipe(Pipe* pipe, string* output)
{
	char pipe_buffer[8192];

	while(true)
	{
		try
		{
			int n = pipe->readBytes(pipe_buffer, sizeof(pipe_buffer));
			if(n == 0)
			{
				break;
			}

			output->append(pipe_buffer, n);
		}
		catch(Poco::ReadFileException& e)
		{
			//
			// All good, probably just nothing to read
			//
			break;
		}
	}
}

void ssh_worker::write_to_pipe(Pipe* pipe, const string& input)
{
	int n = 0;
	while(true)
	{
		try
		{
			n += pipe->writeBytes(input.data() + n, input.size() - n);
			if(n == (int) input.size())
			{
				break;
			}
		}
		catch(Poco::WriteFileException& e)
		{
			//
			// All good, probably just nothing to read
			//
			break;
		}
	}
}

string ssh_worker::get_input(const string& token)
{
	Poco::Mutex::ScopedLock lock(m_sessions_lock);

	string input;

	map<string, ssh_session>::iterator it = m_sessions.find(token);
	if(it != m_sessions.end())
	{
		input = it->second.m_pending_input;
		it->second.m_pending_input.clear();
	}

	return input;
}

void ssh_worker::send_input(const string& token, const string& input)
{
	Poco::Mutex::ScopedLock lock(m_sessions_lock);

	g_log->information("Adding new input to session " + token);

	map<string, ssh_session>::iterator it = m_sessions.find(token);
	if(it != m_sessions.end())
	{
		it->second.m_pending_input.append(input);
	}
}
