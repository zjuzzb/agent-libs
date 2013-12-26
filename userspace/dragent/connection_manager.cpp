#include "connection_manager.h"

//
// SSL callback: since the SSL is managed by ELB, he sends an encrypted alert type 21 when
// no instances are available in the backend. Of course Poco is bugged and doesn't recognize
// that, so we need to abort the connection ourselves otherwise we'll keep talking to noone:
// https://forums.aws.amazon.com/message.jspa?messageID=453844
//
static bool g_ssl_alert_received = false;

static void g_ssl_callback(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg)
{
	//
	// Code borrowed from s_cb.c in openssl
	//
	if(write_p == 0 &&
		content_type == 21 &&
		len == 2 &&
		((const unsigned char*)buf)[1] == 0)
	{
		g_ssl_alert_received = true;
	}
}

connection_manager::connection_manager(dragent_configuration* configuration) :
	m_sa(NULL),
	m_socket(NULL),
	m_configuration(configuration)
{
	Poco::Net::initializeSSL();	
}

connection_manager::~connection_manager()
{
	if(m_sa)
	{
		delete m_sa;
		m_sa = NULL;
	}

	if(m_socket)
	{
		delete m_socket;
		m_socket = NULL;
	}

	Poco::Net::uninitializeSSL();
}

StreamSocket* connection_manager::get_socket()
{
	// ASSERT(m_socket);
	return m_socket;
}

void connection_manager::init()
{
	if(m_configuration->m_server_addr != "" && m_configuration->m_server_port != 0)
	{
		m_sa = new Poco::Net::SocketAddress(m_configuration->m_server_addr, m_configuration->m_server_port);

		if(m_configuration->m_ssl_enabled)
		{
			g_log->information("SSL enabled, initializing context");

			Poco::Net::Context::Ptr ptrContext = new Poco::Net::Context(
				Poco::Net::Context::CLIENT_USE, 
				"", 
				"", 
				m_configuration->m_ssl_ca_certificate, 
				Poco::Net::Context::VERIFY_STRICT, 
				9, 
				false, 
				"ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");

			Poco::Net::SSLManager::instance().initializeClient(0, 0, ptrContext);

			SSL_CTX* ssl_ctx = ptrContext->sslContext();
			if(ssl_ctx)
			{
				SSL_CTX_set_msg_callback(ssl_ctx, g_ssl_callback);
			}
		}
	}
}

void connection_manager::connect()
{
	ASSERT(m_socket == NULL);
	ASSERT(m_sa != NULL);

	if(m_configuration->m_ssl_enabled)
	{
		m_socket = new Poco::Net::SecureStreamSocket(*m_sa, m_configuration->m_server_addr);
		((Poco::Net::SecureStreamSocket*) m_socket)->verifyPeerCertificate();

		g_log->information("SSL identity verified");
	}
	else
	{
		m_socket = new Poco::Net::StreamSocket(*m_sa);
	}

	//
	// Set the send buffer size for the socket
	//
	m_socket->setSendBufferSize(m_configuration->m_transmitbuffer_size);
	m_socket->setSendTimeout(1000000);
	m_socket->setReceiveTimeout(1000000);

	g_log->information("Connected to collector");
}

void connection_manager::close()
{
	ASSERT(m_socket != NULL);
	if(m_socket != NULL)
	{
		delete m_socket;
		m_socket = NULL;
	}
}
