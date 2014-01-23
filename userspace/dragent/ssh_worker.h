#pragma once

#include "main.h"
#include "protocol.h"
#include "draios.pb.h"
#include "configuration.h"

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
	uint32_t m_port;
};

class ssh_session
{
public:
	string m_pending_input;
};

class ssh_worker : public Runnable
{
public:
	ssh_worker(dragent_configuration* configuration, protocol_queue* queue, 
		const string& token, const ssh_settings& settings);
	~ssh_worker();
	
	void run();

	static void send_input(const string& token, const string& input);

private:
	void send_error(const string& error);
	void prepare_response(draiosproto::ssh_data* response);
	void queue_response(const draiosproto::ssh_data& response);
	void read_from_pipe(Pipe* pipe, string* output);
	void write_to_pipe(Pipe* pipe, const string& output);

	static void add_session(const string& token, const ssh_session& session);
	static void delete_session(const string& token);
	static string get_input(const string& token);

	static const string m_name;
	static Mutex m_sessions_lock;
	static map<string, ssh_session> m_sessions;

	dragent_configuration* m_configuration;
	protocol_queue* m_queue;
	string m_token;
	ssh_settings m_ssh_settings;
};
