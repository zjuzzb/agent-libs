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
#include <Poco/Net/StreamSocketImpl.h>
#include <Poco/Net/SecureStreamSocket.h>
#include <Poco/Net/SSLException.h>
#include <Poco/Net/SSLManager.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <sstream>
#include <thread>
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

bool load_certs(SSL_CTX* ctx, std::string cert_fn, std::string key_fn)
{
	int ret;

	FILE* certf = fopen(cert_fn.c_str(), "r");
	FILE* keyf = fopen(key_fn.c_str(), "r");
	X509* cert_x509 = PEM_read_X509(certf, NULL, NULL, NULL);
	if (cert_x509 == nullptr)
	{
		LOG_WARNING("Error reading certificate " + cert_fn);
		return false;
	}

	EVP_PKEY* pkey = PEM_read_PrivateKey(keyf, NULL, NULL, NULL);
	if (pkey == nullptr)
	{
		LOG_WARNING("Error reading private key " + key_fn);
		return false;
	}

	ret = SSL_CTX_use_certificate(ctx, cert_x509);
	if (ret <= 0)
	{
		LOG_WARNING("Error using certificate: %d", ret);
		ERR_print_errors_fp(stderr);
		return false;
	}
	ret = SSL_CTX_use_PrivateKey(ctx, pkey);
	if (ret <= 0)
	{
		LOG_WARNING("Error using private key: %d", ret);
		ERR_print_errors_fp(stderr);
		return false;
	}
	LOG_INFO("Loaded cert %s and key %s", cert_fn.c_str(), key_fn.c_str());
	return true;
}

// Build a meaningless PKEY structure with an RSA signature
// Why in the world would we do this?
// Even if we don't support SSL certificate validation, newer versions of
// OpenSSL will still fail the connection if there is no certificate
// present, regardless of whether or not the peer attempts to validate
// it. So the agent will generate a new private key and certificate
// every single time, which will fulfill the requirement of OpenSSL that
// a certificate be present.
EVP_PKEY* generate_key()
{
	EVP_PKEY* ret = EVP_PKEY_new();
	if (ret == nullptr)
	{
		LOG_ERROR("Could not create public key");
		return nullptr;
	}

	BIGNUM* bn = BN_new();
	BN_set_word(bn, RSA_F4);
	RSA* rsa = RSA_new();
	RSA_generate_key_ex(rsa, 2048, bn, NULL);
	BN_free(bn);

	if (!EVP_PKEY_assign_RSA(ret, rsa))
	{
		LOG_ERROR("Could not assign RSA key to public key");
		EVP_PKEY_free(ret);
		return nullptr;
	}

	return ret;
}

// Build a meaningless certificate
// See the header above generate_key for the explanation of why we do this.
X509* generate_x509(EVP_PKEY* public_key)
{
	// Days per year * hours per day * minutes per hour * seconds per minute
	const uint32_t seconds_per_year = 365 * 24 * 60 * 60;
	X509* ret = X509_new();

	if (!ret)
	{
		LOG_ERROR("Could not create certificate");
		return nullptr;
	}

	ASN1_INTEGER_set(X509_get_serialNumber(ret), 1);

	// Expire one year from now
	X509_gmtime_adj(X509_get_notBefore(ret), 0);
	X509_gmtime_adj(X509_get_notAfter(ret), seconds_per_year);

	X509_set_pubkey(ret, public_key);

	// Add our own custom entries to the subject name and copy it to the issuer name
	X509_NAME* name = X509_get_subject_name(ret);
	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"US", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"Sysdig", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"sysdigcloud.com", -1, -1, 0);

	X509_set_issuer_name(ret, name);

	if (!X509_sign(ret, public_key, EVP_sha1()))
	{
		LOG_ERROR("Error signing certificate");
		X509_free(ret);
		return nullptr;
	}

	return ret;
}

bool generate_cert(SSL_CTX* ctx)
{
	EVP_PKEY* pkey = generate_key();
	if (!pkey)
	{
		return false;
	}
	X509* cert_x509 = generate_x509(pkey);
	if (!cert_x509)
	{
		EVP_PKEY_free(pkey);
		return false;
	}

	int ret = SSL_CTX_use_certificate(ctx, cert_x509);
	if (ret <= 0)
	{
		LOG_WARNING("Error using certificate: %d", ret);
		ERR_print_errors_fp(stderr);
		X509_free(cert_x509);
		EVP_PKEY_free(pkey);
		return false;
	}
	ret = SSL_CTX_use_PrivateKey(ctx, pkey);
	if (ret <= 0)
	{
		LOG_WARNING("Error using private key: %d", ret);
		ERR_print_errors_fp(stderr);
		X509_free(cert_x509);
		EVP_PKEY_free(pkey);
		return false;
	}
	X509_free(cert_x509);
	EVP_PKEY_free(pkey);
	LOG_INFO("Generated internal cert and key");
	return true;
}
}

const milliseconds SOCKET_TCP_TIMEOUT = seconds(60);
const char* const PREFERRED_CIPHERS = "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4:@STRENGTH";

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

// Statics
std::atomic<bool> cm_socket::m_listen(false);
std::atomic<uint32_t> cm_socket::m_num_listen_threads(0);
std::atomic<uint64_t> cm_socket::faults(0);

void cm_socket::listen_thread_loop(int listen_fd,
                                   SSL_CTX* ssl_ctx,
                                   std::function<void (cm_socket*, void*)> callback,
                                   std::function<void (error_type, int, void*)> err_callback,
                                   void* cb_ctx)
{
	++m_num_listen_threads;

	const bool resolve_incoming = false;
	const std::chrono::milliseconds timeout(1000);
	// Structures needed for poll()
	struct pollfd fds[1] = {listen_fd, POLLIN};
	error_type errdesc = ERR_NONE;
	int errval = 0;

	while (m_listen)
	{
		int ret;
		struct sockaddr_in addr = {};
		uint32_t len = sizeof(addr);
		SSL* ssl = nullptr;
		char client_name[NI_MAXHOST] = {};
		uint16_t client_port = 0;
		cm_socket* incoming_sock;

		// Use poll() to get a timeout while blocking
		ret = ::poll(fds, 1, timeout.count());

		if (ret < 0 || check_fault(FP_BAD_POLL_RETURN))
		{
			LOG_ERROR("Error listening for new connections: %s (%d)",
			          strerror(errno),
			          errno);
			errdesc = ERR_POLL_RETURN;
			errval = errno;
			m_listen = false;
			continue;
		}

		if ((ret > 0 && fds[0].revents != POLLIN) || check_fault(FP_POLLERR))
		{
			// We can receive POLLERR, POLLHUP, and POLLINVAL. Given that this
			// is a passive listening socket, none of these are expected.
			LOG_ERROR("Unexpected event while listening for incoming connections: %d",
			          fds[0].revents);
			errdesc = ERR_POLL_EVENT;
			errval = fds[0].revents;
			m_listen = false;
			continue;
		}

		if (ret == 0)
		{
			// Poll timed out. This is expected and normal.
			continue;
		}

		// Accept incoming connections on the passive socket
		len = sizeof(addr);
		int conn_fd = ::accept(listen_fd, (struct sockaddr*)&addr, &len);
		if (conn_fd < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
		{
			// There can be a race condition where there's a pending
			// connection that causes poll() to return, but by the time
			// we get to accept() the connection has dropped. This is
			// not an error.
			continue;
		}
		if (conn_fd < 0)
		{
			LOG_ERROR("Error while accepting incoming connection: %d", errno);
			continue;
		}

		if (resolve_incoming)
		{
			getnameinfo((struct sockaddr*)&addr,
			            sizeof(addr),
			            client_name,
			            sizeof(client_name),
			            NULL,
			            0,
			            0);
		}

		// If resolving failed (or resolve_incoming is false), use IP address
		if (client_name[0] == '\0')
		{
			strncpy(client_name, inet_ntoa(addr.sin_addr), sizeof(client_name) - 1);
			client_name[sizeof(client_name) - 1] = '\0';
		}
		client_port = ntohs(addr.sin_port);

		LOG_INFO("Received connection from client %s:%hu", client_name, client_port);

		if (ssl_ctx)
		{
			// Do the SSL connection
			ssl = SSL_new(ssl_ctx);
			ret = SSL_set_fd(ssl, conn_fd);
			if (ret != 1)
			{
				ERR_print_errors_fp(stderr);
				int err = SSL_get_error(ssl, ret);
				LOG_ERROR("SSL error on incoming connection: %d : %d", ret, err);
				continue;
			}

			ret = SSL_accept(ssl);
			if (ret <= 0)
			{
				int err = SSL_get_error(ssl, ret);
				if (err == SSL_ERROR_WANT_READ ||
				    err == SSL_ERROR_WANT_WRITE)
				{
					LOG_ERROR("SSL_ERROR_WANT_READ/WRITE not handled yet");
					// Add socket to the list of FDs for polling?
				}
				ERR_print_errors_fp(stderr);
				LOG_ERROR("SSL error accepting incoming connection: %d : %d", ret, err);
				continue;
			}

			// Build the socket
			auto* sock = new cm_openssl_socket(ssl_ctx);
			sock->connect(ssl);
			incoming_sock = sock;
		}
		else // Non-SSL case
		{
			auto* sock = new cm_poco_socket();
			sock->connect(conn_fd);
			incoming_sock = sock;
		}

		callback(incoming_sock, cb_ctx); // The callback now owns the socket
		incoming_sock = nullptr;
	} // End listen loop
	LOG_INFO("Stopped listening for incoming connections");
	::close(listen_fd);
	SSL_CTX_free(ssl_ctx);

	if (errdesc != ERR_NONE)
	{
		// We encountered an error. Now that we've torn down the listening
		// socket, call the error callback.
		err_callback(errdesc, errval, cb_ctx);
	}
	--m_num_listen_threads;
}

bool cm_socket::listen(cm_socket::port_spec pspec,
                       std::function<void(cm_socket*, void*)> callback,
                       std::function<void (error_type, int, void*)> err_callback,
                       void* cb_ctx)
{
	const uint32_t listen_queue = SOMAXCONN;
	// Set up listening socket
	struct sockaddr_in addr;
	int listen_fd = -1;
	int ret = 0;

	// Needed for SSL connection
	SSL_CTX* ssl_ctx = nullptr;

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(pspec.port);

	listen_fd = socket(addr.sin_family, SOCK_STREAM, IPPROTO_TCP);
	if (listen_fd < 0)
	{
		LOG_ERROR("Unable to create socket: %d", listen_fd);
		return false;
	}

	// Allow addr reuse (helps when restarting the agent)
	int val = 1;
	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0)
	{
		LOG_ERROR("Unable to modify socket options: %s (%d)", strerror(errno), errno);
		::close(listen_fd);
		return false;
	}

	// Set socket non-blocking
	int flags = fcntl(listen_fd, F_GETFL, 0);
	if (flags == -1)
	{
		LOG_ERROR("Unable to get flags for socket: %s (%d)", strerror(errno), errno);
		::close(listen_fd);
		return false;
	}
	flags |= O_NONBLOCK;
	ret = fcntl(listen_fd, F_SETFL, flags);
	if (ret != 0)
	{
		LOG_ERROR("Unable to set flags for socket: %s (%d)", strerror(errno), errno);
		return false;
	}

	// Bind to the port
	ret = ::bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr));
	if (ret < 0)
	{
		LOG_ERROR("Unable to bind to address: %s (%d)", strerror(errno), errno);
		::close(listen_fd);
		return false;
	}

	// Now listen for incoming connections
	ret = ::listen(listen_fd, listen_queue);
	if (ret < 0)
	{
		LOG_ERROR("Unable to listen on socket: %d", ret);
		return false;
	}

	if (pspec.ssl)
	{
		// Create the SSL context
		ssl_ctx = SSL_CTX_new(TLS_server_method());
		if (!ssl_ctx)
		{
			LOG_ERROR("Unable to build SSL context");
			ERR_print_errors_fp(stderr);
			return false;
		}

		SSL_CTX_set_cipher_list(ssl_ctx, PREFERRED_CIPHERS);
		SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, nullptr);
		generate_cert(ssl_ctx);
		SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
		// We don't have cert validation at this point
	}

	LOG_INFO("Listening for incoming connections on fd %d port %hu", listen_fd, pspec.port);
	m_listen = true;

	// Run listen thread
	std::thread t(listen_thread_loop,
	              listen_fd,
	              ssl_ctx,
	              callback,
	              err_callback,
	              cb_ctx);

	t.detach();
	return m_listen;
}

void cm_socket::stop_listening(bool wait)
{
	m_listen = false;

	if (wait)
	{
		while (!m_listen && m_num_listen_threads != 0)
		{
			std::this_thread::sleep_for(milliseconds(50));
		}
	}
}

bool cm_socket::poll(const std::list<poll_sock>& sock_list,
                     std::list<poll_sock>& out_list,
                     std::chrono::milliseconds timeout)
{
	if (sock_list.empty())
	{
		return false;
	}

	uint32_t nfds = sock_list.size();
	std::vector<struct pollfd> fds(nfds);
	bool success = false;
	auto itr = sock_list.begin();

	// Pass 1: Build the FD list
	uint32_t idx = 0;
	for (auto psock : sock_list)
	{
		int sock_fd = psock.sock->get_fd();
		fds[idx].fd = sock_fd;
		fds[idx].events = POLLIN;
		++idx;
	}

	int ret = ::poll(fds.data(), fds.size(), timeout.count());

	if (ret < 0)
	{
		LOG_ERROR("Error polling socket for data: %s (%d)",
		          strerror(errno),
		          errno);
		success = false;
		goto bail;
	}

	out_list.clear();
	success = true;

	if (ret == 0)
	{
		goto bail;
	}

	// Pass 2: Build the return list
	for (uint32_t i = 0; i < nfds; ++i, ++itr)
	{
		if (fds[i].revents == POLLIN ||
		    fds[i].revents == POLLERR ||
		    fds[i].revents == POLLHUP)
		{
			out_list.emplace_back(itr->sock, itr->ctx);
		}
	}

bail:
	return success;
}

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
	m_ctx = SSL_CTX_new(TLS_client_method());
	m_server = m_proxy = nullptr;

	ASSERT(m_ctx != nullptr);
	if (m_ctx == nullptr)
	{
		// This is a "should never happen" error
		LOG_ERROR("Unable to build SSL context for client");
		return;
	}
	m_ssl_ctx_owned = true;

	// Set options on SSL context
	if (c_ssl_verify_certificate.get_value())
	{
		SSL_CTX_set_verify(m_ctx, SSL_VERIFY_PEER, nullptr);
		SSL_CTX_set_verify_depth(m_ctx, 9);
	}
	else
	{
		SSL_CTX_set_verify(m_ctx, SSL_VERIFY_NONE, nullptr);
	}
	const long flags = SSL_OP_NO_COMPRESSION | SSL_OP_CIPHER_SERVER_PREFERENCE;
	SSL_CTX_set_options(m_ctx, flags);
	SSL_CTX_set_min_proto_version(m_ctx, TLS1_2_VERSION);
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
}

cm_openssl_socket::cm_openssl_socket(SSL_CTX* ctx)
{
	m_ssl = nullptr;
	m_socket = -1;
	m_valid = false;
	m_ssl_ctx_owned = false;
	m_server = m_proxy = nullptr;

	m_ctx = ctx;
}

cm_openssl_socket::~cm_openssl_socket()
{
	close();
	if (m_server && m_proxy)
	{
		BIO_free_all(m_server);
	}
	else if (m_ssl)
	{
		SSL_free(m_ssl);
	}
	if (m_ssl_ctx_owned && m_ctx) SSL_CTX_free(m_ctx);
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
	int res;
	// openssl sockets must be given an already-connected socket. This method
	// will then establish a secure connection to the collector.
	if (m_ctx == nullptr)
	{
		return false;
	}
	SSL *ssl = SSL_new(m_ctx);

	res = SSL_set_fd(ssl, sock_fd);
	if (res != 1)
	{
		int err = SSL_get_error(ssl, res);
		LOG_ERROR("Error setting sock fd: %d (%d)", res, err);
		SSL_free(ssl);
		return false;
	}

	ASSERT(!hostname.empty());
	SSL_set1_host(ssl, hostname.c_str());
	SSL_set_tlsext_host_name(ssl, hostname.c_str());

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

bool cm_openssl_socket::connect(SSL* ssl)
{
	m_ssl = ssl;
	m_socket = SSL_get_fd(ssl);
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

	int ret = ::poll(fds, 1, 0);

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

int cm_openssl_socket::get_fd() const
{
	if (is_valid())
	{
		if (m_socket != -1)
		{
			return m_socket;
		}
		else
		{
			ASSERT(m_server != nullptr);
			// A BIO-backed SSL socket
			return BIO_get_fd(m_server, nullptr);
		}
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

bool cm_poco_socket::connect(int sockfd)
{
	auto* impl = new Poco::Net::StreamSocketImpl(sockfd);
	// The StreamSocket takes ownership of the SocketImpl pointer
	m_sockptr = std::make_shared<Poco::Net::StreamSocket>(impl);

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

	try
	{
		return m_sockptr->receiveBytes(buf, len, MSG_WAITALL);
	}
	catch (const Poco::Net::ConnectionResetException& ex)
	{
		LOG_INFO("Connection reset on receive");
		return -ECONNRESET;
	}
	catch (const Poco::TimeoutException& ex)
	{
		return -ETIMEDOUT;
	}
	catch (const Poco::IOException& ex)
	{
		return -ex.code();
	}
}

bool cm_poco_socket::has_pending() const
{
	if (!m_sockptr)
	{
		return false;
	}
	return m_sockptr->poll(Poco::Timespan(), Poco::Net::Socket::SELECT_READ |
	                                         Poco::Net::Socket::SELECT_ERROR);
}

int cm_poco_socket::translate_error(int ret) const
{
	return ret;
}

int cm_poco_socket::get_fd() const
{
	return m_sockptr->impl()->sockfd();
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

	LOG_DEBUG("Connecting to " + sa.host().toString() + " (" + hostname + ")");

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
	return m_sockptr->poll(Poco::Timespan(), Poco::Net::Socket::SELECT_READ |
	                                         Poco::Net::Socket::SELECT_ERROR);
}

int cm_poco_secure_socket::translate_error(int ret) const
{
	return ret;
}

int cm_poco_secure_socket::get_fd() const
{
	return m_sockptr->impl()->sockfd();
}
