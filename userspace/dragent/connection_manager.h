#pragma once

#include "main.h"
#include "configuration.h"

class connection_manager
{
public:
	connection_manager();
	~connection_manager();

	void init(dragent_configuration* configuration);
	StreamSocket* get_socket();
	void connect();
	void close();

private:

	SocketAddress* m_sa;
	StreamSocket* m_socket;
	const dragent_configuration* m_configuration;
};
