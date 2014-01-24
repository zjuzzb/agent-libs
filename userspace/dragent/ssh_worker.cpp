#include "ssh_worker.h"

#include <sys/types.h>
#include <sys/wait.h>

const string ssh_worker::m_name = "ssh_worker";

Mutex ssh_worker::m_sessions_lock;
map<string, ssh_worker_session> ssh_worker::m_sessions;

ssh_worker::ssh_worker(dragent_configuration* configuration, protocol_queue* queue,
		const string& token, const ssh_settings& settings):
	
	m_configuration(configuration),
	m_queue(queue),
	m_token(token),
	m_ssh_settings(settings),
	m_libssh_session(NULL),
	m_libssh_key(NULL),
	m_libssh_channel(NULL)
{
}

ssh_worker::~ssh_worker()
{
	delete_session(m_token);

	if(m_libssh_key)
	{
		ssh_key_free(m_libssh_key);
		m_libssh_key = NULL;
	}

	if(m_libssh_channel)
	{
		ssh_channel_free(m_libssh_channel);
		m_libssh_channel = NULL;
	}

	if(m_libssh_session)
	{
		ssh_free(m_libssh_session);
		m_libssh_session = NULL;
	}
}

void ssh_worker::run()
{
	//
	// A quick hack to automatically delete this object
	//
	SharedPtr<ssh_worker> ptr(this);

	ssh_worker_session session;
	add_session(m_token, session);
	
	g_log->information(m_name + ": Opening SSH session, token " + m_token);

	m_libssh_session = ssh_new();
	if(m_libssh_session == NULL)
	{
		send_error("Error creating libssh session");
		return;
	}

	ssh_options_set(m_libssh_session, SSH_OPTIONS_HOST, "localhost");
	ssh_options_set(m_libssh_session, SSH_OPTIONS_USER, m_ssh_settings.m_user.c_str());

	if(m_ssh_settings.m_port)
	{
		ssh_options_set(m_libssh_session, SSH_OPTIONS_PORT, &m_ssh_settings.m_port);
	}

	if(ssh_connect(m_libssh_session) != SSH_OK)
	{
		send_error(string("ssh_connect: ") + ssh_get_error(m_libssh_session));
		return;
	}

	if(!m_ssh_settings.m_password.empty())
	{
		if(ssh_userauth_password(m_libssh_session, NULL, m_ssh_settings.m_password.c_str()) != SSH_AUTH_SUCCESS)
		{
			send_error(string("ssh_userauth_password: ") + ssh_get_error(m_libssh_session));
			return;
		}
	}
	else if(!m_ssh_settings.m_key.empty())
	{
		m_libssh_key = ssh_key_new();
		if(m_libssh_key == NULL)
		{
			send_error("Error creating ssh key");
			return;
		}

		const char* passphrase = NULL;
		if(!m_ssh_settings.m_passphrase.empty())
		{
			passphrase = m_ssh_settings.m_passphrase.c_str();
		}

		if(ssh_pki_import_privkey_base64(m_ssh_settings.m_key.c_str(), passphrase, NULL, NULL, &m_libssh_key) != SSH_OK)
		{
			send_error("Error importing ssh key");
			return;
		}

		if(ssh_userauth_publickey(m_libssh_session, NULL, m_libssh_key) != SSH_AUTH_SUCCESS)
		{
			send_error(string("ssh_userauth_publickey: ") + ssh_get_error(m_libssh_session));
			return;
		}
	}
	else
	{
		send_error("No password or key specified");
		return;		
	}

	m_libssh_channel = ssh_channel_new(m_libssh_session);
	if(m_libssh_channel == NULL)
	{
		send_error("Error opening ssh channel");
		return;
	}

	if(ssh_channel_open_session(m_libssh_channel) != SSH_OK)
	{
		send_error(string("ssh_channel_open_session: ") + ssh_get_error(m_libssh_session));
		return;
	}

	if(ssh_channel_request_pty(m_libssh_channel) != SSH_OK)
	{
		send_error(string("ssh_channel_request_pty: ") + ssh_get_error(m_libssh_session));
		return;
	}

	if(ssh_channel_change_pty_size(m_libssh_channel, 80, 24) != SSH_OK)
	{
		send_error(string("ssh_channel_change_pty_size: ") + ssh_get_error(m_libssh_session));
		return;
	}

	if(ssh_channel_request_shell(m_libssh_channel) != SSH_OK)
	{
		send_error(string("ssh_channel_request_shell: ") + ssh_get_error(m_libssh_session));
		return;
	}

	while(!dragent_configuration::m_terminate &&
		ssh_channel_is_open(m_libssh_channel) &&
		!ssh_channel_is_eof(m_libssh_channel))
	{
		string input = get_input(m_token);
		write_to_channel(input);
		string output;
		read_from_channel(&output);

		if(output.size())
		{
			//
			// Report the partial output
			//
			draiosproto::ssh_data response;
			prepare_response(&response);
			response.set_data(output);

			g_log->information("Sending partial output (" 
				+ NumberFormatter::format(output.size()) + ")");

			queue_response(response);
		}

		Thread::sleep(100);
		continue;
	}

	g_log->information("SSH session terminated");

	// string std_out;
	// read_from_pipe(&out_pipe, &std_out);
	// string std_err;
	// read_from_pipe(&err_pipe, &std_err);

	// draiosproto::ssh_data response;
	// prepare_response(&response);

	// std_out.append(std_err);

	// if(std_out.size())
	// {
	// 	response.set_data(std_out);
	// }

	// response.set_exit_val(WEXITSTATUS(status));

	// queue_response(response);

	ssh_disconnect(m_libssh_session);

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

void ssh_worker::read_from_channel(string* output)
{
	char buffer[8192];

	while(true)
	{
		int res = ssh_channel_read_nonblocking(m_libssh_channel, buffer, sizeof(buffer), 0);
		if(res == SSH_ERROR)
		{
			ASSERT(false);
		}

		if(res == 0)
		{
			break;
		}

		output->append(buffer, res);
	}
}

void ssh_worker::write_to_channel(const string& input)
{
	int n = 0;
	while(n != (int) input.size())
	{
		int res = ssh_channel_write(m_libssh_channel, input.data() + n, input.size() - n);
		if(res == SSH_ERROR)
		{
			ASSERT(false);
		}

		n += res;
	}
}

string ssh_worker::get_input(const string& token)
{
	Poco::Mutex::ScopedLock lock(m_sessions_lock);

	string input;

	map<string, ssh_worker_session>::iterator it = m_sessions.find(token);
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

	map<string, ssh_worker_session>::iterator it = m_sessions.find(token);
	if(it != m_sessions.end())
	{
		it->second.m_pending_input.append(input);
	}
}

void ssh_worker::add_session(const string& token, const ssh_worker_session& session)
{
	Poco::Mutex::ScopedLock lock(m_sessions_lock);

	m_sessions.insert(pair<string, ssh_worker_session>(token, session));
}

void ssh_worker::delete_session(const string& token)
{
	Poco::Mutex::ScopedLock lock(m_sessions_lock);

	m_sessions.erase(token);
}

