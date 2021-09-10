#ifndef CYGWING_AGENT
#pragma once

#include <functional>
#include <memory>
#include <string>

#include <grpc++/grpc++.h>

#include "common_logger.h"
#include "stream_grpc_status.h"
#include "agent-prom.grpc.pb.h"

/**
 * A Promscrape specific GRPC interface class to create unary
 * GRPC connections and methods to act on the data transmitted
 * in those connections.
 * 
 */
class prom_unarygrpc_iface
{
public:
	prom_unarygrpc_iface(const std::string& sock) : m_sock(sock)
	{
	}
typedef std::function<void(bool successful, agent_promscrape::Empty& empty)> resp_cb_t;

/**
 * Provides an interface for derived classes to implement their
 * own mechanisms for starting and maintaining a unary GRPC
 * connection
 * 
 * @param boot_ts - The start time of the unary connection
 * @param config - Agent promscrape config 
 * @param response_cb  - Response callback to be called as part
 *  				   of the incoming connection response.
 * 
 * @return bool - Returns true if connection is successful,
 *  	   false otherwise.
 */
virtual bool start_unary_connection(int64_t boot_ts, std::shared_ptr<agent_promscrape::Config>& config, resp_cb_t response_cb) = 0;

/**
 * Reset an exisitng connection
 */
virtual void reset() = 0;

/**
 * Process the response queue.
 */
virtual void process_queue() = 0;

protected:
	std::string m_sock;
};

/**
 * A Promscrape specific GRPC interface class to create
 * streaming GRPC connections and methods to act on the data
 * transmitted in those connections.
 * 
 */
class prom_streamgrpc_iface
{
public:
	prom_streamgrpc_iface(const std::string& sock) : m_sock(sock)
	{
	}

typedef std::function<void(streaming_grpc::Status status, agent_promscrape::ScrapeResult& result)> resp_cb_t;

/**
 * Provides an interface for derived classes to implement their
 * own mechanisms for starting and maintaining a streaming GRPC
 * connection.
 * 
 * @param boot_ts  - The start time for a connection.
 * @param response_cb  - Response callback to be called as part
 *  				   of the incoming connection response.
 */
virtual void start_stream_connection(int64_t boot_ts, resp_cb_t response_cb) = 0;

/**
 * Indicate if a connection was started successfully.
 * 
 */
virtual bool started() = 0;

/**
 * Reset an existing connection
 */
virtual void reset() = 0;

/**
 * Process the response queue
 */ 
virtual void process_queue() = 0;

protected:
	std::string m_sock;
};

#endif // CYGWING_AGENT
