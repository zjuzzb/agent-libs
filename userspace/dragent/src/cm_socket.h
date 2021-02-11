#pragma once

#include <openssl/ssl.h>

#include <Poco/Net/StreamSocket.h>
#include <Poco/Net/SecureStreamSocket.h>

#include <atomic>
#include <cstdint>
#include <functional>
#include <list>
#include <map>
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
	////// Types
	using ptr = std::shared_ptr<cm_socket>;

	struct port_spec
	{
		uint16_t port;
		bool ssl;
	};

	struct poll_sock
	{
		cm_socket* sock;
		void* ctx;

		poll_sock(cm_socket* _sock, void* _ctx): sock(_sock), ctx(_ctx) {}
	};

	enum error_type
	{
		ERR_NONE,
		ERR_POLL_RETURN,
		ERR_POLL_EVENT,
	};

	////// Static methods

	/**
	 * Open a passive listening socket which will accept incoming connections.
	 *
	 * This function creates its own internal thread for listening.
	 *
	 * @param pspec     Descriptor of the port to listen on
	 * @param callback  Callback invoked on new connection
	 * @param cb_ctx    Context object to be passed back into the callback
	 *
	 * Note: The callback is invoked synchronously, so a nontrivial callback
	 *       can block the listen thread from accepting new connections.
	 *
	 * The callback takes the following arguments:
	 *   cm_socket*  A pointer to the new socket created from an incoming
	 *               connection request.
	 *   void*       The context object provided by the caller to this function
	 *
	 * @retval true   The passive socket is created and listening
	 * @retval false  There was an error
	 */
	static bool listen(port_spec pspec,
	                   std::function<void(cm_socket*, void*)> callback,
	                   std::function<void (error_type, int, void*)> err_callback,
	                   void* cb_ctx);

	/**
	 * Stop listening for incoming connections.
	 *
	 * Cleans up the passive listening socket and stops the thread created by
	 * the listen() method.
	 *
	 * @param wait  If true, waits for all threads to complete before returning.
	 *              If false, returns immediately.
	 */
	static void stop_listening(bool wait);

	/**
	 * Block until at least one socket becomes readable.
	 *
	 * This function will return once a socket becomes readable. If the
	 * function blocks longer than timeout with no socket becoming readable,
	 * the function will return an empty list.
	 *
	 * @param sock_list  The list of sockets to poll
	 * @param out_list   The list of sockets which have become readable
	 * @param timeout    Only block for this long
	 *
	 * @return  true   poll was successful and out_list is valid (but may be empty)
	 * @return  false  poll was unsuccessful. The contents of out_list are undefined
	 */
	static bool poll(const std::list<poll_sock>& sock_list,
	                 std::list<poll_sock>& out_list,
	                 std::chrono::milliseconds timeout);

	/**
	 * Gets the connection timeout set in the config file.
	 *
	 * This timeout can be overridden both manually (by calling set_connect_timeout
	 * on a cm_socket interface) and automatically by a subclass. The overridden
	 * timout can be obtained by calling get_connect_timeout. However, if the user
	 * needs to retrieve the timeout specified in the config file (for example,
	 * if the cm_socket hasn't been created yet so there is no instance), this
	 * static method provides the interface to do that.
	 */
	static std::chrono::milliseconds get_default_connect_timeout();

	/**
	 * Walk over the CA path search list and return the first one that exists.
	 *
	 * Note: we have to return a new string by value as we potentially alter
	 * the string in the search path (substituting $OPENSSLDIR with the actual path)
	 */
	static std::string find_ca_cert_path(const std::vector<std::string>& search_paths);


	////// Instance methods
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
	 * Gets the file descriptor for the backing socket (if available).
	 *
	 * @return fd  The file descriptor for the backing socket
	 * @return -1  The socket is not connected or is invalid
	 */
	virtual int get_fd() const = 0;

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

protected:
	std::chrono::milliseconds m_connect_timeout;
	std::chrono::milliseconds m_send_recv_timeout;

private:
	static void listen_thread_loop(int listen_fd,
	                               SSL_CTX* ssl_ctx,
	                               std::function<void (cm_socket*, void*)> callback,
	                               std::function<void (error_type, int, void*)> err_callback,
	                               void* cb_ctx);

	static std::atomic<bool> m_listen; ///< Should the listen thread(s) run?
	static std::atomic<uint32_t> m_num_listen_threads;
	//^ C++20 has a counting semaphore, but we don't have compiler support

public:
	// Fault injection system for testing error conditions it's hard to produce
	// organically in a unit test
	enum fault_point
	{
		FP_BAD_POLL_RETURN,
		FP_POLLERR,

		FP_TEST,
		FP_MAX
	};
	static_assert(FP_MAX < 64, "Only 64 faults allowed");

	static std::atomic<uint64_t> faults;

#ifdef SYSDIG_TEST
	static void set_fault(fault_point fp)
	{
		uint8_t fault_num = (uint8_t)fp;
		faults |= (1 << fault_num);
	}

	static bool check_fault(fault_point fp)
	{
		uint8_t fault_num = (uint8_t)fp;
		bool ret = (faults & (1 << fault_num)) > 0;

		// There's a window here where multiple calls to check_fault could
		// all return true. That's fine, because every possible interleaving
		// is valid, and this is just code for unit testing. If this is a
		// problem...don't do that.

		faults &= ~(1 << fault_num);
		return ret;
	}
#else
	static void set_fault(fault_point fp) {}
	static bool check_fault(fault_point fp) { return false; }
#endif
};

/**
 * A cm_socket backed by OpenSSL over a POSIX socket.
 *
 * openssl_sockets work differently from all the other sockets here. Whereas
 * most of the other sockets connect when the user calls connect(), openssl
 * sockets receive an already-connected socket as a parameter to connect().
 */
class cm_openssl_socket : public cm_socket
{
public:
	cm_openssl_socket(const std::vector<std::string>& ca_cert_paths,
	                  const std::string& ssl_ca_certificate,
	                  bool verify_certificate);
	cm_openssl_socket(SSL_CTX* ctx);
	~cm_openssl_socket();

	virtual bool connect(const std::string& hostname, uint16_t port) override;
	bool connect(int sock_fd, const std::string& hostname);
	bool connect(BIO* proxy);
	bool connect(SSL* ssl);
	virtual void close() override;

	virtual int64_t send(const uint8_t* buf, uint32_t len) override;
	virtual int64_t receive(uint8_t* buf, uint32_t len) override;
	virtual bool has_pending() const override;
	virtual int translate_error(int ret) const override;
	virtual int get_fd() const override;

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
	BIO* m_server;
	BIO* m_proxy;
	int m_socket;
	bool m_valid;
	bool m_ssl_ctx_owned;
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
	bool connect(int sock_fd);
	virtual void close() override;

	virtual int64_t send(const uint8_t* buf, uint32_t len) override;
	virtual int64_t receive(uint8_t* buf, uint32_t len) override;
	virtual bool has_pending() const override;
	virtual int translate_error(int ret) const override;
	virtual int get_fd() const override;
private:
	std::shared_ptr<Poco::Net::StreamSocket> m_sockptr;
};

/**
 * A cm_socket backed by a Poco secure socket
 */
class cm_poco_secure_socket : public cm_socket
{
public:
	cm_poco_secure_socket(const std::vector<std::string>& cert_paths,
	                      const std::string& cert_authority,
	                      bool verify_certificate);
	~cm_poco_secure_socket();

	virtual bool connect(const std::string& hostname, uint16_t port) override;
	virtual void close() override;

	virtual int64_t send(const uint8_t* buf, uint32_t len) override;
	virtual int64_t receive(uint8_t* buf, uint32_t len) override;
	virtual bool has_pending() const override;
	virtual int translate_error(int ret) const override;
	virtual int get_fd() const override;
private:
	std::shared_ptr<Poco::Net::SecureStreamSocket> m_sockptr;
};
