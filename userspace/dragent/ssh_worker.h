#pragma once

#include "main.h"
#include "protocol.h"
#include "draios.pb.h"
#include "configuration.h"

#define LIBSSH_STATIC 1
#include <libssh/libssh.h> 

class ssh_settings
{
public:
	ssh_settings():
		m_port(0)
	{
	}

	string m_user;
	string m_password;
	string m_key;
	string m_passphrase;
	uint32_t m_port;
};

class ssh_worker : public Runnable
{
public:
	class pending_message
	{
	public:
		pending_message():
			m_new_message(false),
			m_close(false)
		{
		}

		string m_input;
		bool m_new_message;
		bool m_close;
	};

	ssh_worker(dragent_configuration* configuration, protocol_queue* queue, 
		const string& token, const ssh_settings& settings);
	~ssh_worker();
	
	void run();

	static void request_input(const string& token, const string& input);
	static void request_close(const string& token);

private:
	void send_error(const string& error);
	void prepare_response(draiosproto::ssh_data* response);
	void queue_response(const draiosproto::ssh_data& response);
	void read_from_channel(string* output, bool std_err);
	void write_to_channel(const string& input);

	static void add_pending_messages(const string& token);
	static void delete_pending_messages(const string& token);
	static bool get_pending_messages(const string& token, pending_message* message);

	static const string m_name;
	static Mutex m_pending_messages_lock;
	static map<string, pending_message> m_pending_messages;

	static const uint64_t m_session_timeout_ns = 600 * 1000000000LL;

	dragent_configuration* m_configuration;
	protocol_queue* m_queue;
	string m_token;
	ssh_settings m_ssh_settings;
	uint64_t m_last_activity_ns;
	ssh_session m_libssh_session;
	ssh_key m_libssh_key;
	ssh_channel m_libssh_channel;
};
