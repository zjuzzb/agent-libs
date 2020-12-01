#include "cm_socket.h"

#include <common_logger.h>
#include <configuration_manager.h>

#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <poll.h>
#include <netinet/tcp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <Poco/File.h>
#include <Poco/NumberFormatter.h>
#include <Poco/Path.h>
#include <Poco/SharedPtr.h>
#include <Poco/Timespan.h>
#include <Poco/Crypto/X509Certificate.h>
#include <Poco/Net/Context.h>
#include <Poco/Net/InvalidCertificateHandler.h>
#include <Poco/Net/PrivateKeyPassphraseHandler.h>
#include <Poco/Net/SocketAddress.h>
#include <Poco/Net/StreamSocket.h>
#include <Poco/Net/SecureStreamSocket.h>
#include <Poco/Net/SSLException.h>
#include <Poco/Net/SSLManager.h>

#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <sstream>
#include <vector>
#include <chrono>

using std::chrono::microseconds;
using std::chrono::milliseconds;
using std::chrono::seconds;

COMMON_LOGGER();

#ifndef TCP_USER_TIMEOUT
// Define it here because old glibc versions do not have this flag (eg, Centos6)
#define TCP_USER_TIMEOUT 18 /* How long for loss retry before timeout */
#endif

namespace
{
// Find the host's default OPENSSLDIR
// This is best effort for now, so don't log at warn/error
const std::string& get_openssldir()
{
	static std::string path = "";

	if (!path.empty())
	{
		return path;
	}

	errno = 0;
	FILE* out = popen("openssl version -d 2>&1", "r");
	if (!out)
	{
		LOG_INFO("openssl popen() failed: %s", strerror(errno));
		return path;
	}

	// Sample output:
	// $ openssl version -d
	// OPENSSLDIR: "/usr/lib/ssl"
	//
	// It should only be one line, but read multiple lines in case the
	// format changes. Also the while control structure works better
	char buf[256];
	int ii = 0;
	const int max_lines = 10;
	while (ii < max_lines && fgets(buf, sizeof(buf), out))
	{
		ii++;
		std::string out_str(buf);
		LOG_DEBUG("openssl read from popen(): " + out_str);

		// Would use std::regex if we had compiler support
		std::string start_targ("OPENSSLDIR: \"");
		auto start_pos = out_str.find(start_targ);
		if (start_pos == std::string::npos)
		{
			continue;
		}
		start_pos += start_targ.size();
		std::string end_targ("\"");
		auto end_pos = out_str.find(end_targ, start_pos);
		if (end_pos == std::string::npos)
		{
			continue;
		}

		path = out_str.substr(start_pos, end_pos - start_pos);
		LOG_DEBUG("found OPENSSLDIR: " + path);
		break;
	}

	int ret = pclose(out);
	LOG_DEBUG("openssl pclose() exit code: %d", WEXITSTATUS(ret));
	return path;
}
}

const milliseconds SOCKET_TCP_TIMEOUT = seconds(60);
const char* const PREFERRED_CIPHERS = "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH";

// Socket config values

type_config<uint32_t> c_connect_timeout_ms(60000, // 60 seconds
                                           "Timeout for connecting to the backend.",
                                           "connect_timeout");

type_config<uint32_t> c_socket_timeout_ms(1000,
                                          "Timeout for send and receive operations to the "
                                          "collector, in milliseconds.",
                                          "socket_timeout");

type_config<uint32_t>::ptr c_transmitbuffer_size =
    type_config_builder<uint32_t>(256 * 1024,
                                  "Size of the socket buffer for transmitting "
                                  "metrics data to the backend.",
                                  "transmitbuffer_size")
        .hidden()
        .build();


type_config<bool> c_ssl_verify_certificate(true,
                                           "Should the agent verify the SSL certificate "
                                           "sent by the collector?",
                                           "ssl_verify_certificate");


cm_socket::cm_socket():
    m_connect_timeout(c_connect_timeout_ms.get_value()),
    m_send_recv_timeout(c_socket_timeout_ms.get_value())
{

}

cm_socket::~cm_socket()
{

}

milliseconds cm_socket::get_connect_timeout() const
{
	return m_connect_timeout;
}

milliseconds cm_socket::get_send_recv_timeout() const
{
	return m_send_recv_timeout;
}

void cm_socket::set_connect_timeout(milliseconds timeout)
{
	m_connect_timeout = timeout;
}

void cm_socket::set_send_recv_timeout(milliseconds timeout)
{
	m_send_recv_timeout = timeout;
}

milliseconds cm_socket::get_default_connect_timeout()
{
	return milliseconds(c_connect_timeout_ms.get_value());
}

std::string cm_socket::find_ca_cert_path(const std::vector<std::string>& search_paths)
{
	std::vector<std::string> failed_paths;
	for (auto path : search_paths)
	{
		auto pos = path.find("$OPENSSLDIR");
		if (pos != std::string::npos)
		{
			path.replace(pos, strlen("$OPENSSLDIR"), get_openssldir());
		}

		LOG_DEBUG("Checking CA path: " + path);
		if (Poco::File(path).exists())
		{
			return path;
		}

		failed_paths.emplace_back(path);
	}

	std::string msg("Could not find any valid CA path, tried:");
	for (const auto& path : failed_paths)
	{
		msg.append(' ' + path);
	}
	LOG_WARNING(msg);
	return "";
}


/**************************************************************************
 * OpenSSL socket
 **************************************************************************/
cm_openssl_socket::cm_openssl_socket(const std::vector<std::string>& ca_cert_paths,
                                     const std::string& ssl_ca_certificate)
{
	int res = -1;
	m_ssl = nullptr;
	m_socket = -1;
	m_valid = false;
	m_ctx = SSL_CTX_new(SSLv23_client_method());
	m_server = m_proxy = nullptr;

	ASSERT(m_ctx != nullptr);
	if (m_ctx == nullptr)
	{
		// This is a "should never happen" error
		LOG_ERROR("Unable to build SSL context for client");
		return;
	}

	// Set options on SSL context
	if (c_ssl_verify_certificate.get_value())
	{
		SSL_CTX_set_verify(m_ctx, SSL_VERIFY_PEER, nullptr);
	}
	else
	{
		SSL_CTX_set_verify(m_ctx, SSL_VERIFY_NONE, nullptr);
	}
	SSL_CTX_set_verify_depth(m_ctx, 9);
	const long flags = SSL_OP_NO_COMPRESSION;
	SSL_CTX_set_options(m_ctx, flags);
	SSL_CTX_set_mode(m_ctx, SSL_MODE_AUTO_RETRY);

	// Tell SSL where the certificates are
	std::string ca_cert_path(find_ca_cert_path(ca_cert_paths));
	res = SSL_CTX_load_verify_locations(m_ctx,
	                                    ssl_ca_certificate.c_str(),
	                                    ca_cert_path.c_str());
	if (res != 1)
	{
		// If this happens the object is still in a valid state, it
		// just will not be able to validate any certs.
		LOG_ERROR("Couldn't load certificate: %d", res);
		return;
	}


	m_ssl = nullptr;
	m_socket = -1;
	m_valid = false;
}

cm_openssl_socket::~cm_openssl_socket()
{
	LOG_WARNING("Destructing");
	close();
	if (m_server && m_proxy)
	{
		BIO_free_all(m_server);
	}
	else if (m_ssl)
	{
		SSL_free(m_ssl);
	}
	if (m_ctx) SSL_CTX_free(m_ctx);
}

bool cm_openssl_socket::connect(const std::string& hostname, uint16_t port)
{
	// The default connect() method will not work for an openssl socket,
	// as it requires an already-connected socket fd which the signature
	// does not provide.
	return false;
}

bool cm_openssl_socket::connect(int sock_fd, const std::string& hostname)
{
	// openssl sockets must be given an already-connected socket. This method
	// will then establish a secure connection to the collector.
	if (m_ctx == nullptr)
	{
		return false;
	}
	SSL *ssl = SSL_new(m_ctx);
	int res = SSL_set_cipher_list(ssl, PREFERRED_CIPHERS);
	if (res != 1)
	{
		LOG_ERROR("Couldn't set cipher list");
		SSL_free(ssl);
		return false;
	}

	res = SSL_set_fd(ssl, sock_fd);
	if (res != 1)
	{
		int err = SSL_get_error(ssl, res);
		LOG_ERROR("Error setting sock fd: %d (%d)", res, err);
		SSL_free(ssl);
		return false;
	}

	if (!hostname.empty())
	{
		SSL_set_tlsext_host_name(ssl, hostname.c_str());
	}

	res = SSL_connect(ssl);
	if (res != 1)
	{
		// This could be due to cert validation. Annoyingly, OpenSSL does not
		// give us a specific useful error code to determine if this is the
		// case (at least that I can find)
		int err = SSL_get_error(ssl, res);
		LOG_ERROR("Could not establish SSL connection to server: %d (%d). "
		          "Perhaps certificate validation failed?",
		          res,
		          err);
		SSL_free(ssl);
		return false;
	}

	LOG_INFO("SSL connection successful");
	m_ssl = ssl;
	m_socket = sock_fd;
	m_valid = true;
	return true;
}

bool cm_openssl_socket::connect(BIO* proxy)
{
	// We receive a BIO object for the proxy, and link one for
	// the remote server
	if (m_ctx == nullptr)
	{
		return false;
	}

	BIO* server = BIO_new_ssl(m_ctx, 1); // 1 = client, 0 = server
	if (server == nullptr)
	{
		LOG_ERROR("Couldn't create SSL BIO object");
		return false;
	}

	// Link BIOs together
	BIO_push(server, proxy);

	SSL* server_ssl = nullptr;
	BIO_get_ssl(server, &server_ssl);
	if (server_ssl == nullptr)
	{
		LOG_ERROR("Couldn't create SSL object for server connection");
		return false;
	}

	int res = SSL_set_cipher_list(server_ssl, PREFERRED_CIPHERS);
	if (res != 1)
	{
		LOG_ERROR("Error setting cipher list: %d", res);
	}

	res = BIO_get_fd(proxy, &m_socket);
	if (res <= 0)
	{
		LOG_ERROR("BIO_get_fd failed: %d", res);
		return false;
	}

	LOG_INFO("SSL connection successful");
	m_ssl = server_ssl;
	m_proxy = proxy;
	m_server = server;
	m_valid = true;
	return true;
}

void cm_openssl_socket::close()
{
	if (m_valid)
	{
		SSL_shutdown(m_ssl);
		if (m_socket > 0)
		{
			::close(m_socket);
		}
	}
	m_socket = -1;
	m_valid = false;
}

int64_t cm_openssl_socket::send(const uint8_t* buf, uint32_t len)
{
	if (!is_valid())
	{
		LOG_ERROR("Attempt to send data on invalid connection");
		return -1;
	}
	return SSL_write(m_ssl, buf, len);
}

int64_t cm_openssl_socket::receive(uint8_t* buf, uint32_t len)
{
	if (!is_valid())
	{
		LOG_ERROR("Attempt to read data on invalid connection");
		return -1;
	}
	return SSL_read(m_ssl, buf, len);
}

bool cm_openssl_socket::has_pending() const
{
	if (m_socket < 0)
	{
		return false;
	}
	struct pollfd fds[1];

	fds[0].fd = m_socket;
	fds[0].events = POLLIN;

	int ret = poll(fds, 1, 0);

	if (ret > 0 && (fds[0].revents & POLLIN))
	{
		return true;
	}

	if (ret < 0)
	{
		LOG_ERROR("Error polling socket: %d", ret);
	}
	return false;
}

int cm_openssl_socket::translate_error(int ret) const
{
	if (m_ssl)
	{
		return SSL_get_error(m_ssl, ret);
	}
	return -1;
}

bool cm_openssl_socket::is_valid() const
{
	return m_valid && m_ssl && (m_socket > 0 || m_server);
}

/***************************************************************************
 * Poco socket (plaintext)
 ***************************************************************************/

cm_poco_socket::cm_poco_socket()
{
}

cm_poco_socket::~cm_poco_socket()
{
}

bool cm_poco_socket::connect(const std::string& hostname, uint16_t port)
{
	m_sockptr = std::make_shared<Poco::Net::StreamSocket>();
	Poco::Net::SocketAddress sa(hostname, port);
	microseconds conn_timeout = m_connect_timeout;
	m_sockptr->connect(sa, conn_timeout.count());

	// Set additional socket options post-connect
	microseconds timeout = m_send_recv_timeout;
	m_sockptr->setSendBufferSize(c_transmitbuffer_size->get_value());
	m_sockptr->setSendTimeout(timeout.count());
	m_sockptr->setReceiveTimeout(timeout.count());

	try
	{
		// This option makes the connection fail earlier in case of unplugged cable
		m_sockptr->setOption(IPPROTO_TCP, TCP_USER_TIMEOUT, (int)SOCKET_TCP_TIMEOUT.count());
	}
	catch (const std::exception&)
	{
		// ignore if kernel does not support this
		// alternatively, could be a setsockopt() call to avoid exception
	}

	return true;
}

void cm_poco_socket::close()
{
	if (m_sockptr)
	{
		m_sockptr->close();
		m_sockptr.reset();
	}
}

int64_t cm_poco_socket::send(const uint8_t* buf, uint32_t len)
{
	if (!m_sockptr)
	{
		return 0;
	}

	int32_t res = 0;
	try
	{
		res = m_sockptr->sendBytes(buf, len);
	}
	catch (const Poco::TimeoutException& e)
	{
		return -ETIMEDOUT;
	}
	catch (const Poco::IOException& e)
	{
		// When the underlying socket times out without sending data, this
		// results in a TimeoutException for SSL connections and EWOULDBLOCK
		// for non-SSL connections, so we'll treat them the same.
		if ((e.code() == POCO_EWOULDBLOCK) || (e.code() == POCO_EAGAIN))
		{
			// We shouldn't risk hanging indefinitely if the EWOULDBLOCK is
			// caused by an attempted send larger than the buffer size
			if (len > c_transmitbuffer_size->get_value())
			{
				LOG_ERROR("Attempted to transmit more data than the buffer can hold (%u > %u): %s",
				          len,
				          c_transmitbuffer_size->get_value(),
				          e.displayText().c_str());
				return -e.code();
			}
			else
			{
				throw;
			}
		}
	}

	return res;
}

int64_t cm_poco_socket::receive(uint8_t* buf, uint32_t len)
{
	if (!m_sockptr)
	{
		return 0;
	}

	return m_sockptr->receiveBytes(buf, len, MSG_WAITALL);
}

bool cm_poco_socket::has_pending() const
{
	if (!m_sockptr)
	{
		return false;
	}
	return m_sockptr->poll(Poco::Timespan(), Poco::Net::Socket::SELECT_READ ||
	                                         Poco::Net::Socket::SELECT_ERROR);
}

int cm_poco_socket::translate_error(int ret) const
{
	return ret;
}

/***************************************************************************
 * Poco socket (SSL)
 ***************************************************************************/

class LoggingCertificateHandler : public Poco::Net::InvalidCertificateHandler
{
public:
	using Poco::Net::InvalidCertificateHandler::InvalidCertificateHandler;

	// Mimicking Poco::Net::ConsoleCertificateHandler but no user input
	virtual void onInvalidCertificate(const void* pSender,
	                                  Poco::Net::VerificationErrorArgs& errorCert)
	{
		LOG_ERROR("Certificate verification failed: %s (%d), Issuer: %s,"
		          "Subject: %s, chain position %d",
		          errorCert.errorMessage().c_str(),
		          errorCert.errorNumber(),
		          errorCert.certificate().issuerName().c_str(),
		          errorCert.certificate().subjectName().c_str(),
		          errorCert.errorDepth());
	}
};

cm_poco_secure_socket::cm_poco_secure_socket(const std::vector<std::string>& cert_paths,
                                             const std::string& cert_authority)
{
	Poco::Net::Context::VerificationMode verification_mode;
	Poco::SharedPtr<LoggingCertificateHandler> invalid_cert_handler = nullptr;
	std::string cert_path;

	if (c_ssl_verify_certificate.get_value())
	{
		verification_mode = Poco::Net::Context::VERIFY_STRICT;
		invalid_cert_handler = new LoggingCertificateHandler(false);
		cert_path = find_ca_cert_path(cert_paths);
		LOG_INFO("SSL CA cert path: " + cert_path);
	}
	else
	{
		verification_mode = Poco::Net::Context::VERIFY_NONE;
	}

	Poco::Net::Context::Ptr ptrContext =
	    new Poco::Net::Context(Poco::Net::Context::CLIENT_USE,
	                           "",
	                           "",
	                           cert_path,
	                           verification_mode,
	                           9,
	                           false,
	                           PREFERRED_CIPHERS);

	try
	{
		LOG_INFO("openssl loading cert: %s", cert_authority.c_str());
		Poco::Crypto::X509Certificate ca_cert(cert_authority);
		ptrContext->addCertificateAuthority(ca_cert);
	}
	catch (const Poco::Net::SSLException& e)
	{
		// thrown by addCertificateAuthority()
		LOG_ERROR("Unable to add ssl ca certificate: %s", e.message().c_str());
	}
	catch (const Poco::IOException& e)
	{
		// thrown by X509Certificate constructor
		LOG_ERROR("Unable to read ssl ca certificate: %s", e.message().c_str());
	}
	catch (...)
	{
		LOG_ERROR("Unable to load ssl ca certificate: %s", cert_authority.c_str());
	}

	// If the above fails, this call will still succeed but certificate validation
	// will likely fail as well, causing the connect to fail.
	Poco::Net::SSLManager::instance().initializeClient(0, invalid_cert_handler, ptrContext);
}

cm_poco_secure_socket::~cm_poco_secure_socket()
{
}

bool cm_poco_secure_socket::connect(const std::string& hostname, uint16_t port)
{
	m_sockptr = std::make_shared<Poco::Net::SecureStreamSocket>();
	Poco::Net::SocketAddress sa(hostname, port);

	m_sockptr->setLazyHandshake(true);
	m_sockptr->setPeerHostName(hostname);
	microseconds conn_timeout = m_connect_timeout;
	m_sockptr->connect(sa, conn_timeout.count());

	// This is done to prevent getting stuck forever waiting during the handshake
	// if the server doesn't speak to us
	m_sockptr->setSendTimeout(conn_timeout.count());
	m_sockptr->setReceiveTimeout(conn_timeout.count());

	LOG_INFO("Performing SSL handshake");
	int32_t ret = m_sockptr->completeHandshake();

	if (ret == 1)
	{
		m_sockptr->verifyPeerCertificate();
		LOG_INFO("SSL identity verified");
	}
	else
	{
		LOG_ERROR("SSL Handshake didn't complete");
		return false;
	}

	// Set additional socket options post-connect
	microseconds timeout = m_send_recv_timeout;
	m_sockptr->setSendBufferSize(c_transmitbuffer_size->get_value());
	m_sockptr->setSendTimeout(timeout.count());
	m_sockptr->setReceiveTimeout(timeout.count());

	try
	{
		// This option makes the connection fail earlier in case of unplugged cable
		m_sockptr->setOption(IPPROTO_TCP, TCP_USER_TIMEOUT, (int)SOCKET_TCP_TIMEOUT.count());
	}
	catch (const std::exception&)
	{
		// ignore if kernel does not support this
		// alternatively, could be a setsockopt() call to avoid exception
	}

	return true;
}

void cm_poco_secure_socket::close()
{
	if (m_sockptr)
	{
		m_sockptr->close();
		m_sockptr.reset();
	}
}

int64_t cm_poco_secure_socket::send(const uint8_t* buf, uint32_t len)
{
	if (!m_sockptr)
	{
		return 0;
	}

	bool retry = false;
	uint32_t num_retries = 0;
	int res = 0;
	do
	{
		try
		{
			res = m_sockptr->sendBytes(buf, len);
		}
		catch (const Poco::TimeoutException& e)
		{
			// Handle TimeoutException because the other socket types behave
			// differently in the case of a timeout, and I want uniform behavior
			// across all types to avoid the caller having to know too much
			// about the underlying details of the socket implementation.
			return -ETIMEDOUT;
		}
		catch (const Poco::IOException& e)
		{
			LOG_DEBUG("Got IOException %s", e.displayText().c_str());
			// When the underlying socket times out without sending data, this
			// results in a TimeoutException for SSL connections and EWOULDBLOCK
			// for non-SSL connections, so we'll treat them the same.
			if ((e.code() == POCO_EWOULDBLOCK) || (e.code() == POCO_EAGAIN))
			{
				// We shouldn't risk hanging indefinitely if the EWOULDBLOCK is
				// caused by an attempted send larger than the buffer size
				if (len > c_transmitbuffer_size->get_value())
				{
					LOG_ERROR("Attempted to transmit more data than the buffer can hold (%u > %u): %s",
					          len,
					          c_transmitbuffer_size->get_value(),
					          e.displayText().c_str());
					return -EINVAL;
				}
				else
				{
					return -ETIMEDOUT;
				}
			}
			else
			{
				LOG_DEBUG("Rethrowing IOException to be handled by connection manager");
				throw;
			}
		}

		// These are not expected conditions as the socket is nonblocking.
		// I handle them specially here because these are an idiosyncracy of
		// the Poco implementation specifically.
		if (res == Poco::Net::SecureStreamSocket::ERR_SSL_WANT_READ)
		{
			LOG_ERROR("Internal error: Unexpected SSL_WANT_READ on a write. Disconnecting.");
			return -1;
		}
		if (res == Poco::Net::SecureStreamSocket::ERR_SSL_WANT_WRITE)
		{
			if (retry)
			{
				// We already retried once. Time to bail.
				LOG_ERROR("Internal error: Retry of SSL_WANT_WRITE failed. Disconnecting. "
				          "If the problem persists, try restarting the agent.");
				return -1;
			}

			LOG_WARNING("Got SSL_WANT_WRITE on a write. Retrying write.");
			retry = true;
		}
	} while (retry && ++num_retries < 2);

	return res;
}

int64_t cm_poco_secure_socket::receive(uint8_t* buf, uint32_t len)
{
	if (!m_sockptr)
	{
		return 0;
	}
	bool retry = false;
	uint32_t num_retries = 0;
	int res = 0;

	do
	{
		res = m_sockptr->receiveBytes(buf, len, MSG_WAITALL);

		// These are not expected conditions as the socket is nonblocking.
		// I handle them specially here because these are an idiosyncracy of
		// the Poco implementation specifically.
		if (res == Poco::Net::SecureStreamSocket::ERR_SSL_WANT_READ)
		{
			if (retry)
			{
				LOG_ERROR("Internal error: Unexpected SSL_WANT_READ on a write. Disconnecting.");
				return -1;
			}
			LOG_INFO("Got SSL_WANT_READ on receive. Retrying read.");
			retry = true;
			continue;
		}
		if (res == Poco::Net::SecureStreamSocket::ERR_SSL_WANT_WRITE)
		{
			LOG_WARNING("Internal error: Got SSL_WANT_WRITE on receive. Disconnecting.");
			return -1;
		}
	} while (retry && ++num_retries < 2);

	return res;
}

bool cm_poco_secure_socket::has_pending() const
{
	if (!m_sockptr)
	{
		return false;
	}
	return m_sockptr->poll(Poco::Timespan(), Poco::Net::Socket::SELECT_READ ||
	                                         Poco::Net::Socket::SELECT_ERROR);
}

int cm_poco_secure_socket::translate_error(int ret) const
{
	return ret;
}
