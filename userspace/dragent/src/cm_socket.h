#pragma once

#include <openssl/ssl.h>

#include <Poco/Net/StreamSocket.h>
#include <Poco/Net/SecureStreamSocket.h>

#include <cstdint>
#include <memory>
#include <string>
#include <chrono>

/**
 * @brief Encapsulates a socket for use by the connection manager.
 *
 * The connection manager offers several different types of connection:
 *  - Standard, unencrypted connection
 *  - SSL-encrypted connection
 *  - Unencrypted HTTP proxy
 *  - Encrypted HTTP proxy
 *
 * This class provides a common set of methods for each connection type.
 */
class cm_socket
{
public:
	using ptr = std::shared_ptr<cm_socket>;

	cm_socket();
	virtual ~cm_socket();

	/**
	 * Connect to the given host:port.
	 *
	 * @return Whether the connect succeeded or not.
	 */
	virtual bool connect(const std::string& hostname, uint16_t port) = 0;

	/**
	 * Close the socket.
	 *
	 * After a call to close() the socket will no longer be connected.
	 * It is up to each implementation whether a call to connect() after
	 * a call to close() is valid. If a subsequent reconnect using
	 * connect() is invalid, the connect() method will return false.
	 */
	virtual void close() = 0;

	/**
	 * Send len bytes from buf to the server.
	 *
	 * @return >0 Number of bytes written
	 * @return 0  Connection terminated on remote end
	 * @return <0 Socket error
	 */
	virtual int64_t send(const uint8_t* buf, uint32_t len) = 0;

	/**
	 * Receive up to len bytes from server into buf.
	 *
	 * Receive will block until there is at least one byte available to read.
	 * It will then read as many bytes as are available without blocking, up
	 * to len bytes.
	 *
	 * @return >0 Number of bytes read
	 * @return 0  Connection terminated on remote end
	 * @return <0 Socket error
	 */
	virtual int64_t receive(uint8_t* buf, uint32_t len) = 0;

	/**
	 * Will a receive() on this socket object block?
	 *
	 * @return true  A call to receive() on this socket will not block.
	 * @return false A call to receive() on this socket may block.
	 */
	virtual bool has_pending() const = 0;

	/**
	 * Convert an errorful return from send() or receive() into a
	 * more useable format.
	 *
	 * Depending on the underlying implementation of the socket, a
	 * call to translate_error may be required to get the most useful
	 * form of the errorful return.
	 */
	virtual int translate_error(int ret) const = 0;

	/**
	 * Get the currently configured connection timeout.
	 */
	std::chrono::milliseconds get_connect_timeout() const;

	/**
	 * Get the currently configured socket timeout.
	 */
	std::chrono::milliseconds get_send_recv_timeout() const;

	/**
	 * Set the timeout to be used on connect()
	 */
	void set_connect_timeout(std::chrono::milliseconds timeout);

	/**
	 * Set the timeout to be used on send() and receive()
	 */
	void set_send_recv_timeout(std::chrono::milliseconds timeout);

	static std::chrono::milliseconds get_default_connect_timeout();

protected:
	std::chrono::milliseconds m_connect_timeout;
	std::chrono::milliseconds m_send_recv_timeout;
};

/**
 * A cm_socket backed by OpenSSL over a POSIX socket.
 *
 * openssl_sockets work differently from all the other sockets here. Whereas
 * most of the other sockets connect when the user calls connect(), openssl
 * sockets receive a file descriptor for an already-connected socket in the
 * constructor.
 */
class cm_openssl_socket : public cm_socket
{
public:
	cm_openssl_socket(const std::vector<std::string>& ca_cert_paths,
	                  const std::string& ssl_ca_certificate);
	~cm_openssl_socket();

	virtual bool connect(const std::string& hostname, uint16_t port) override;
	bool connect(int sock_fd, const std::string& hostname);
	virtual void close() override;

	virtual int64_t send(const uint8_t* buf, uint32_t len) override;
	virtual int64_t receive(uint8_t* buf, uint32_t len) override;
	virtual bool has_pending() const override;
	virtual int translate_error(int ret) const override;

	/**
	 * Returns whether the socket is valid for use.
	 *
	 * Because of the differences in how openssl sockets work (see class header
	 * for an explanation), we need a way to determine if the socket is valid
	 * (i.e. the constructor succeeded).
	 */
	bool is_valid() const;
private:
	SSL* m_ssl;
	SSL_CTX* m_ctx;
	int m_socket;
	bool m_valid;
};

/**
 * A cm_socket based off a Poco socket
 */
class cm_poco_socket : public cm_socket
{
public:
	cm_poco_socket();
	~cm_poco_socket();

	virtual bool connect(const std::string& hostname, uint16_t port) override;
	virtual void close() override;

	virtual int64_t send(const uint8_t* buf, uint32_t len) override;
	virtual int64_t receive(uint8_t* buf, uint32_t len) override;
	virtual bool has_pending() const override;
	virtual int translate_error(int ret) const override;
private:
	std::shared_ptr<Poco::Net::StreamSocket> m_sockptr;
};

/**
 * A cm_socket backed by a Poco secure socket
 */
class cm_poco_secure_socket : public cm_socket
{
public:
	cm_poco_secure_socket(const std::vector<std::string>& cert_paths, const std::string& cert_authority);
	~cm_poco_secure_socket();

	virtual bool connect(const std::string& hostname, uint16_t port) override;
	virtual void close() override;

	virtual int64_t send(const uint8_t* buf, uint32_t len) override;
	virtual int64_t receive(uint8_t* buf, uint32_t len) override;
	virtual bool has_pending() const override;
	virtual int translate_error(int ret) const override;
private:
	std::shared_ptr<Poco::Net::SecureStreamSocket> m_sockptr;
};
