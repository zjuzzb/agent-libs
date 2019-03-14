#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

#include "sinsp.h"
#include "sinsp_int.h"
#include "../../driver/ppm_ringbuffer.h"

#ifdef HAS_ANALYZER
#include "parsers.h"
#include "analyzer_int.h"
#include "analyzer.h"
#include "analyzer_thread.h"
#include "connectinfo.h"
#include "metrics.h"
#include "draios.pb.h"
#include "delays.h"
#include "scores.h"
#include "procfs_parser.h"
#include "sinsp_errno.h"
#include "sched_analyzer.h"
#include "analyzer_fd.h"
#include "statsite_proxy.h"
#include "baseliner.h"

///////////////////////////////////////////////////////////////////////////////
// sinsp_proto_detector implementation
///////////////////////////////////////////////////////////////////////////////
const char* sql_querystart_toks[] = {"select",
		"insert",
		"set ",
		"create",
		"delete",
		"drop",
		"replace",
		"update",
		"use ",
		"show",
		"lock",
		"unlock",
		"alter"
};

sinsp_proto_detector::sinsp_proto_detector(sinsp_configuration* config)
{
	m_http_options_intval = (*(uint32_t*)HTTP_OPTIONS_STR);
	m_http_get_intval = (*(uint32_t*)HTTP_GET_STR);
	m_http_head_intval = (*(uint32_t*)HTTP_HEAD_STR);
	m_http_post_intval = (*(uint32_t*)HTTP_POST_STR);
	m_http_put_intval = (*(uint32_t*)HTTP_PUT_STR);
	m_http_delete_intval = (*(uint32_t*)HTTP_DELETE_STR);
	m_http_trace_intval = (*(uint32_t*)HTTP_TRACE_STR);
	m_http_connect_intval = (*(uint32_t*)HTTP_CONNECT_STR);
	m_http_resp_intval = (*(uint32_t*)HTTP_RESP_STR);
	m_sinsp_config = config;
}

sinsp_partial_transaction::type sinsp_proto_detector::detect_proto(sinsp_evt *evt, 
	sinsp_partial_transaction *trinfo, 
	sinsp_partial_transaction::direction trdir,
	uint8_t* buf, uint32_t buflen)
{
	uint16_t serverport = evt->m_fdinfo->get_serverport();

	//
	// Make sure there are at least 4 bytes
	//
	if(buflen >= MIN_VALID_PROTO_BUF_SIZE)
	{
		//
		// Detect HTTP
		//
		if(*(uint32_t*)buf == m_http_get_intval ||
				*(uint32_t*)buf == m_http_post_intval ||
				*(uint32_t*)buf == m_http_put_intval ||
				*(uint32_t*)buf == m_http_delete_intval ||
				*(uint32_t*)buf == m_http_trace_intval ||
				*(uint32_t*)buf == m_http_connect_intval ||
				*(uint32_t*)buf == m_http_options_intval ||
				(*(uint32_t*)buf == m_http_resp_intval && buf[4] == '/'))
		{
			//ASSERT(trinfo->m_protoparser == NULL);
			sinsp_http_parser* st = new sinsp_http_parser;
			trinfo->m_protoparser = (sinsp_protocol_parser*)st;

			return sinsp_partial_transaction::TYPE_HTTP;
		}
		//
		// Detect mysql
		//
		else if(serverport == SRV_PORT_MYSQL)
		{
			uint8_t* tbuf;
			uint32_t tbuflen;
			uint32_t stsize = trinfo->m_reassembly_buffer.get_size();

			if(stsize != 0)
			{
				trinfo->m_reassembly_buffer.copy((char*)buf, buflen);
				tbuf = (uint8_t*)trinfo->m_reassembly_buffer.get_buf();
				tbuflen = stsize + buflen;
			}
			else
			{
				tbuf = buf;
				tbuflen = buflen;
			}

			if(tbuflen > 5)	// min length
			{
				//
				// This detects a server greetings message, which is the first message sent by the server
				//
				if(*(uint16_t*)tbuf == tbuflen - 4 // first 3 bytes are length
					&& tbuf[2] == 0x00 // 3rd byte of packet length
					&& tbuf[3] == 0) // Sequence number is zero for the beginning of a query
				{
					sinsp_mysql_parser* st = new sinsp_mysql_parser;
					trinfo->m_protoparser = (sinsp_protocol_parser*)st;
					return sinsp_partial_transaction::TYPE_MYSQL;
				}
				else
				{
					//
					// This detects a query that is received as a fragmented buffer.
					// Usually this happens server side, since the server starts with a 4 byte read 
					// to detect the message and then reads the rest of the payload.
					//
					if(tbuf[0] == 3)
					{
						uint32_t downcase_buf;
						memcpy(&downcase_buf, tbuf+1, sizeof(uint32_t));
						downcase_buf |= 0x20202020; // downcase all chars
						for(uint32_t j = 0; 
							j < sizeof(sql_querystart_toks) / sizeof(sql_querystart_toks[0]);
							j++)
						{
							if(downcase_buf == *(uint32_t*)sql_querystart_toks[j])
							{
								sinsp_mysql_parser* st = new sinsp_mysql_parser;
								trinfo->m_protoparser = (sinsp_protocol_parser*)st;
								return sinsp_partial_transaction::TYPE_MYSQL;
							}
						}
					}
					else if(tbuflen > 8)
					{
						//
						// This detects a query that is received as a NON fragmented buffer.
						//
						if(tbuf[4] == 3)
						{
							uint32_t downcase_buf;
							memcpy(&downcase_buf, tbuf+5, sizeof(uint32_t));
							downcase_buf |= 0x20202020; // downcase all chars
							for(uint32_t j = 0; 
								j < sizeof(sql_querystart_toks) / sizeof(sql_querystart_toks[0]);
								j++)
							{
								if(downcase_buf == *(uint32_t*)sql_querystart_toks[j])
								{
									sinsp_mysql_parser* st = new sinsp_mysql_parser;
									trinfo->m_protoparser = (sinsp_protocol_parser*)st;
									return sinsp_partial_transaction::TYPE_MYSQL;
								}
							}
						}
					}
				}
			}
		}
		else if(serverport == SRV_PORT_POSTGRES)
		{
			uint8_t* tbuf;
			uint32_t tbuflen;
			uint32_t stsize = trinfo->m_reassembly_buffer.get_size();

			if(stsize != 0)
			{
				trinfo->m_reassembly_buffer.copy((char*)buf, buflen);
				tbuf = (uint8_t*)trinfo->m_reassembly_buffer.get_buf();
				tbuflen = stsize + buflen;
			}
			else
			{
				tbuf = buf;
				tbuflen = buflen;
			}

			// XXX do we really want to unconditionally ignore the reassembly buffer?
			// XXX if we do, why even populate it at all?
			tbuf=buf;
			tbuflen = buflen;

			if(tbuflen > 5)	// min length
			{
				if( tbuf[0] == 'Q' ) // Prepare statement commmand
				{
					uint32_t downcase_buf;
					memcpy(&downcase_buf, tbuf+5, sizeof(uint32_t));
					downcase_buf |= 0x20202020; // downcase all chars
					for(uint32_t j = 0;
						j < sizeof(sql_querystart_toks) / sizeof(sql_querystart_toks[0]);
						j++)
					{
						if(downcase_buf == *(uint32_t*)sql_querystart_toks[j])
						{
							sinsp_postgres_parser* st = new sinsp_postgres_parser;
							trinfo->m_protoparser = (sinsp_protocol_parser*)st;
							return sinsp_partial_transaction::TYPE_POSTGRES;
						}
					}
				}
				else if( tbuf[0] == 'P' ) // Prepare statement commmand
				{
					uint32_t downcase_buf;
					memcpy(&downcase_buf, tbuf+6, sizeof(uint32_t));
					downcase_buf |= 0x20202020; // downcase all chars
					for(uint32_t j = 0;
						j < sizeof(sql_querystart_toks) / sizeof(sql_querystart_toks[0]);
						j++)
					{
						if(downcase_buf == *(uint32_t*)sql_querystart_toks[j])
						{
							sinsp_postgres_parser* st = new sinsp_postgres_parser;
							trinfo->m_protoparser = (sinsp_protocol_parser*)st;
							return sinsp_partial_transaction::TYPE_POSTGRES;
						}
					}
				}
				else if( *(uint32_t*)(tbuf+sizeof(uint32_t)) == 0x00000300 ) // startup command
				{
					sinsp_postgres_parser* st = new sinsp_postgres_parser;
					trinfo->m_protoparser = (sinsp_protocol_parser*)st;
					return sinsp_partial_transaction::TYPE_POSTGRES;
				} else if( tbuf[0] == 'E' && htonl(*(uint32_t*)(tbuf+1)) < 2000 ) // error or execute command
				{
					sinsp_postgres_parser* st = new sinsp_postgres_parser;
					trinfo->m_protoparser = (sinsp_protocol_parser*)st;
					return sinsp_partial_transaction::TYPE_POSTGRES;
				}
			}
		}
		else if(buflen >= 16 && (
				*(int32_t*)(buf+12) == 1 ||
				( *(int32_t*)(buf+12) > 2000 && *(int32_t*)(buf+12) < 2008 )
				)
				)
		{
			sinsp_mongodb_parser* st = new sinsp_mongodb_parser;
			trinfo->m_protoparser = (sinsp_protocol_parser*)st;
			return sinsp_partial_transaction::TYPE_MONGODB;
		}
		else if((buf[0] >= 0x14 && buf[0] <= 0x18) && // First byte matches TLS frame type
				 buf[1] == 3 && // Matches TLS major version
				(buf[2] >= 0 && buf[2] <= 3) && // Matches TLS minor version 
				// Besides detecting that it's TLS, we check if port belongs
				// to well-known client/server protocol port
				m_sinsp_config->get_known_ports().test(serverport)) 
		{
			trinfo->m_protoparser = new sinsp_tls_parser();
			return sinsp_partial_transaction::TYPE_TLS;
		}
	}

	if(serverport == SRV_PORT_MYSQL)
	{
		//
		// This transaction has not been recognized yet, and the port is
		// the mysql one. Sometimes mysql splits the receive into multiple
		// reads, so we try to buffer this data and try again later
		//
		if((evt->m_fdinfo->is_role_server() && trdir == sinsp_partial_transaction::DIR_IN )||
			(evt->m_fdinfo->is_role_client() && trdir == sinsp_partial_transaction::DIR_OUT))
		{
			if(trdir !=	trinfo->m_direction)
			{
				trinfo->m_reassembly_buffer.clear();
			}

			trinfo->m_reassembly_buffer.copy((char*)buf, buflen);
		}
	}

	//ASSERT(trinfo->m_protoparser == NULL);
	// If we have not yet recognized a protocol, fallback to known client/server ports
	if(m_sinsp_config->get_known_ports().test(serverport))
	{
		trinfo->m_protoparser = NULL;
		return sinsp_partial_transaction::TYPE_IP;
	}
	else
	{
		trinfo->m_protoparser = NULL;
		return sinsp_partial_transaction::TYPE_UNKNOWN;
	}
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_analyzer_fd_listener implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_analyzer_fd_listener::sinsp_analyzer_fd_listener(sinsp* inspector, sinsp_analyzer* analyzer):
	m_proto_detector(analyzer->get_configuration())
{
	m_inspector = inspector; 
	m_analyzer = analyzer;
	m_sinsp_config = analyzer->get_configuration();
}

bool sinsp_analyzer_fd_listener::patch_network_role(sinsp_threadinfo* ptinfo, sinsp_fdinfo_t* pfdinfo, bool incoming)
{
	//
	// This should be disabled for the moment
	//
	ASSERT(false);

	bool is_sip_local = 
		m_inspector->m_network_interfaces->is_ipv4addr_in_local_machine(pfdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip, ptinfo);
	bool is_dip_local = 
		m_inspector->m_network_interfaces->is_ipv4addr_in_local_machine(pfdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip, ptinfo);

	//
	// If only the client is local, mark the role as client.
	// If only the server is local, mark the role as server.
	//
	if(is_sip_local && !is_dip_local)
	{
		pfdinfo->set_role_client();
		return true;
	}
	else if(is_dip_local && !is_sip_local)
	{
		pfdinfo->set_role_server();
		return true;
	}

	//
	// Both addresses are local
	//
	ASSERT(is_sip_local && is_dip_local);

	//
	// If this process owns the port, mark it as server, otherwise mark it as client
	//
	if(!ptinfo->is_bound_to_port(pfdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport))
	{
		pfdinfo->set_role_client();
		return true;
	}

	if(!ptinfo->uses_client_port(pfdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport))
	{
		pfdinfo->set_role_server();
		return true;
	}

	//
	// The process owns both the client and server port.
	// We just assume that a server usually starts with a read and a client with a write
	//
	if(!(pfdinfo->m_flags & (sinsp_fdinfo_t::FLAGS_ROLE_CLIENT | sinsp_fdinfo_t::FLAGS_ROLE_SERVER)))
	{
		if(incoming)
		{
			pfdinfo->set_role_server();
		}
		else
		{
			pfdinfo->set_role_client();
		}
	}

	return true;
}

sinsp_connection* sinsp_analyzer_fd_listener::get_ipv4_connection(sinsp_fdinfo_t* fdinfo, const ipv4tuple& tuple, sinsp_evt* evt, int64_t tid, int64_t fd, bool incoming)
{
	sinsp_connection* connection = m_analyzer->get_connection(tuple, evt->get_ts());

	if(connection == nullptr)
	{
		//
		// This is either:
		//  - the first read of a UDP socket
		//  - a TCP socket for which we dropped the accept() or connect()
		// Create a connection entry here and try to automatically detect if this is the client or the server.
		//
		if(fdinfo->is_role_none() && !patch_network_role(evt->m_tinfo, fdinfo, incoming))
		{
			return nullptr;
		}
	}
	else if(connection->m_analysis_flags & sinsp_connection::AF_CLOSED)
	{
		//
		// There is a closed connection with the same key. We drop its content and reuse it.
		// We also mark it as reused so that the analyzer is aware of it
		//

		connection->reset();
		connection->m_analysis_flags = sinsp_connection::AF_REUSED;

		if(fdinfo->is_role_none() && !patch_network_role(evt->m_tinfo, fdinfo, incoming))
		{
			// XXX should we return connection (without adding it to the table???) or nullptr?
			// XXX how can we end up here?
			return connection;
		}
	}
	else if((evt->m_tinfo->m_pid != connection->m_spid || fd != connection->m_sfd) &&
		(evt->m_tinfo->m_pid != connection->m_dpid || fd != connection->m_dfd))
	{
		//
		// We dropped both accept() and connect(), and the connection has already been established
		// when handling a read on the other side.
		//
		if(connection->is_server_only())
		{
			if(fdinfo->is_role_none())
			{
				fdinfo->set_role_client();
			}
		}
		else if(connection->is_client_only())
		{
			if(fdinfo->is_role_none())
			{
				fdinfo->set_role_server();
			}
		}
		else
		{
			//
			// FDs don't match but the connection has not been closed yet.
			// This can happen in case of event drops, or when a connection
			// is accepted by a process and served by another one.
			//
			if(fdinfo->is_role_server())
			{
				connection->reset_server();
			}
			else if(fdinfo->is_role_client())
			{
				connection->reset_client();
			}
			else
			{
				connection->reset();
			}

			connection->m_analysis_flags = sinsp_connection::AF_REUSED;

			if(fdinfo->is_role_none() && !patch_network_role(evt->m_tinfo, fdinfo, incoming))
			{
				// XXX should we return connection (without adding it to the table???) or nullptr?
				// XXX how can we end up here?
				return connection;
			}
		}
	}
	else
	{
		connection->set_state(evt->m_errorcode);
		return connection;
	}

	// add a new connection to the table
	// XXX: what about AF_REUSED connections? given the comments (and code) in patch_network_role,
	// XXX: we expect it to return true and not fall into the `return connection` path, which would mean
	// XXX: we ignore that preexisting connection and create a new one
	string scomm = evt->m_tinfo->get_comm();
	connection = m_analyzer->m_ipv4_connections->add_connection(
		fdinfo->m_sockinfo.m_ipv4info,
		&scomm,
		evt->m_tinfo->m_pid,
		tid,
		fd,
		fdinfo->is_role_client(),
		evt->get_ts(),
		sinsp_connection::AF_NONE,
		0);
	return connection;
}

void sinsp_analyzer_fd_listener::on_read(sinsp_evt *evt, int64_t tid, int64_t fd, sinsp_fdinfo_t* fdinfo,
										 char *data, uint32_t original_len, uint32_t len)
{
	evt->set_iosize(original_len);

	if(fdinfo->is_file())
	{
		analyzer_file_stat* file_stat = get_file_stat(evt->get_thread_info(), fdinfo->m_name);
		if(file_stat)
		{
			file_stat->m_bytes += original_len;
			file_stat->m_time_ns += evt->m_tinfo->m_latency;
		}
	}
	else if(fdinfo->is_ipv4_socket())
	{
		sinsp_connection *connection = nullptr;

		/////////////////////////////////////////////////////////////////////////////
		// Handle the connection
		/////////////////////////////////////////////////////////////////////////////
		if(should_report_network(fdinfo))
		{
			connection = get_ipv4_connection(fdinfo, fdinfo->m_sockinfo.m_ipv4info, evt, tid, fd, true);
		}

		//
		// Attribute the read bytes to the proper connection side
		//
		if(connection == nullptr)
		{
			//
			// This happens when the connection table is full
			//
			return;
		}

		if(fdinfo->is_role_server())
		{
			connection->m_metrics.m_server.add_in(1, original_len);
		}
		else if (fdinfo->is_role_client())
		{
			evt->m_tinfo->m_ainfo->m_th_analysis_flags |= thread_analyzer_info::flags::AF_IS_NET_CLIENT;
			connection->m_metrics.m_client.add_in(1, original_len);
		}
		else
		{
			ASSERT(false);
		}

		//
		// Determine the transaction direction.
		// recv(), recvfrom() and recvmsg() return 0 if the connection has been closed by the other side.
		//
		sinsp_partial_transaction::direction trdir;

		uint16_t etype = evt->get_type();
		if(len == 0 && (etype == PPME_SOCKET_RECVFROM_X || etype == PPME_SOCKET_RECV_X || etype == PPME_SOCKET_RECVMSG_X))
		{
			trdir = sinsp_partial_transaction::DIR_CLOSE;
		}
		else
		{
			trdir = sinsp_partial_transaction::DIR_IN;
		}

		update_transaction(evt, fd, fdinfo, data, original_len, len, connection, trdir);
	}
}

void sinsp_analyzer_fd_listener::on_write(sinsp_evt *evt, int64_t tid, int64_t fd, sinsp_fdinfo_t* fdinfo,
										  char *data, uint32_t original_len, uint32_t len)
{
	evt->set_iosize(original_len);

	if(fdinfo->is_file())
	{
		analyzer_file_stat* file_stat = get_file_stat(evt->get_thread_info(), fdinfo->m_name);
		if(file_stat)
		{
			file_stat->m_bytes += original_len;
			file_stat->m_time_ns += evt->m_tinfo->m_latency;
		}
	}
	else if(fdinfo->is_ipv4_socket())
	{
		sinsp_connection* connection = nullptr;

		/////////////////////////////////////////////////////////////////////////////
		// Handle the connection
		/////////////////////////////////////////////////////////////////////////////

		if(should_report_network(fdinfo))
		{
			connection = get_ipv4_connection(fdinfo, fdinfo->m_sockinfo.m_ipv4info, evt, tid, fd, false);
		}

		//
		// Attribute the read bytes to the proper connection side
		//
		if(connection == nullptr)
		{
			//
			// This happens when the connection table is full
			//
			return;
		}

#ifndef _WIN32
		handle_statsd_write(evt, fdinfo, data, len);
#endif

		if(fdinfo->is_role_server())
		{
			connection->m_metrics.m_server.add_out(1, original_len);
		}
		else if(fdinfo->is_role_client())
		{
			evt->m_tinfo->m_ainfo->m_th_analysis_flags |= thread_analyzer_info::flags::AF_IS_NET_CLIENT;
			connection->m_metrics.m_client.add_out(1, original_len);
		}
		else
		{
			ASSERT(false);
		}

		update_transaction(evt, fd, fdinfo, data, original_len, len, connection,
				   sinsp_partial_transaction::DIR_OUT);
	}
}

#ifndef _WIN32
void sinsp_analyzer_fd_listener::handle_statsd_write(sinsp_evt *evt, sinsp_fdinfo_t *fdinfo, const char *data, uint32_t len) const
{
	// Support for statsd protocol
	static const uint32_t LOCALHOST_IPV4 = 0x0100007F; // network endian representation of 127.0.0.1
	static const uint16_t STATSD_PORT = 8125;

	if(m_analyzer->m_statsite_proxy &&
		fdinfo->is_role_client() &&
		fdinfo->is_udp_socket() &&
		fdinfo->get_serverport() == STATSD_PORT)
	{
		auto tinfo = evt->get_thread_info(false);

#if 0
		// This log line it's useful to debug, but it's not suitable for enabling it always
		uint32_t client_ip = fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip;
		uint32_t server_ip = fdinfo->m_sockinfo.m_ipv4serverinfo.m_ip;
		g_logger.format(sinsp_logger::SEV_DEBUG, "Detected statsd message ipv4: %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u container: %s",
				client_ip & 0xFF,
				(client_ip >>  8) & 0xFF,
				(client_ip >> 16) & 0xFF,
				(client_ip >> 24) & 0xFF,
				fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport,
				server_ip & 0xFF,
				(server_ip >>  8) & 0xFF,
				(server_ip >> 16) & 0xFF,
				(server_ip >> 24) & 0xFF,
				fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport,
				tinfo ? tinfo->m_container_id.c_str() : "<no data>");
#endif

		if(tinfo != nullptr && !tinfo->m_container_id.empty())
		{
			// Send the metric as is, so it will be aggregated by host
			m_analyzer->m_statsite_proxy->send_metric(data, len);
			m_analyzer->m_statsite_proxy->send_container_metric(tinfo->m_container_id, data, len);
		}
		else if(m_analyzer->m_statsd_capture_localhost.load(memory_order_relaxed) ||
			(fdinfo->m_sockinfo.m_ipv4serverinfo.m_ip != LOCALHOST_IPV4) ||
			m_sinsp_config->get_use_host_statsd())
		{
			m_analyzer->m_statsite_proxy->send_metric(data, len);
		}
	}
}
#endif

void sinsp_analyzer_fd_listener::update_transaction(sinsp_evt *evt, int64_t fd, sinsp_fdinfo_t *fdinfo, char *data,
						    uint32_t original_len, uint32_t len, sinsp_connection *connection,
						    sinsp_partial_transaction::direction trdir)
{
	//
	// Check if this is a new transaction that needs to be initialized, and whose
	// protocol needs to be discovered.
	// NOTE: after two turns, we give up discovering the protocol and we consider this
	//       to be just IP.
	//
	sinsp_partial_transaction *trinfo = fdinfo->m_usrstate;

	if(trinfo == NULL)
	{
		fdinfo->m_usrstate = new sinsp_partial_transaction();
		trinfo = fdinfo->m_usrstate;
	}

	if(!trinfo->is_active() ||
	   (trinfo->m_n_direction_switches < 8 && trinfo->m_type <= sinsp_partial_transaction::TYPE_IP))
	{
		//
		// New or just detected transaction. Detect the protocol and initialize the transaction.
		// Note: m_type can be bigger than TYPE_IP if the connection has been reset by something
		//       like a shutdown().
		//
		if(trinfo->m_type <= sinsp_partial_transaction::TYPE_IP)
		{
			sinsp_partial_transaction::type type =
				m_proto_detector.detect_proto(evt, trinfo, trdir,
							      (uint8_t*)data, len);

			trinfo->mark_active_and_reset(type);
		}
		else
		{
			trinfo->mark_active_and_reset(trinfo->m_type);
		}
	}

	//
	// Update the transaction state.
	//
	if(trinfo->m_type != sinsp_partial_transaction::TYPE_UNKNOWN)
	{
		trinfo->update(m_analyzer,
			       evt->m_tinfo,
			       fdinfo,
			       connection,
			       evt->m_tinfo->m_lastevent_ts,
			       evt->get_ts(),
			       evt->get_cpuid(),
			       trdir,
#if _DEBUG
			       evt,
			       fd,
#endif
			       data,
			       original_len,
			       len);
	}
}

void sinsp_analyzer_fd_listener::on_sendfile(sinsp_evt *evt, int64_t fdin, uint32_t len)
{
	int64_t tid = evt->get_tid();

	on_write(evt, tid, evt->m_tinfo->m_lastevent_fd, evt->m_fdinfo, 
		NULL, len, 0);

	sinsp_fdinfo_t* fdinfoin = evt->m_tinfo->get_fd(fdin);
	if(fdinfoin == NULL)
	{
		return;
	}

	on_read(evt, tid, fdin, fdinfoin, 
		NULL, len, 0);
}

void sinsp_analyzer_fd_listener::add_client_ipv4_connection(sinsp_evt *evt)
{
	int64_t tid = evt->get_tid();

	uint8_t flags = sinsp_connection::AF_NONE;
	if (evt->m_fdinfo->is_socket_failed()) {
		flags = sinsp_connection::AF_FAILED;
	} else if (evt->m_fdinfo->is_socket_pending()) {
		flags = sinsp_connection::AF_PENDING;
	}

	//
	// Add the tuple to the connection table
	//
	string scomm = evt->m_tinfo->get_comm();

	m_analyzer->m_ipv4_connections->add_connection(evt->m_fdinfo->m_sockinfo.m_ipv4info,
									 &scomm,
									 evt->m_tinfo->m_pid,
									 tid,
									 evt->m_tinfo->m_lastevent_fd,
									 true,
									 evt->get_ts(),
									 flags,
									 evt->m_errorcode);

	evt->m_tinfo->m_ainfo->m_th_analysis_flags |= thread_analyzer_info::flags::AF_IS_NET_CLIENT;

}

void sinsp_analyzer_fd_listener::on_connect(sinsp_evt *evt, uint8_t* packed_data)
{
	uint8_t family = *packed_data;

	//
	// Connection and transaction handling
	//
	// Since UDP sockets don't generate traffic
	// with connect, ignore them here. We'll
	// handle the connection at the first read/write
	if((family == PPM_AF_INET || family == PPM_AF_INET6) &&
			should_report_network(evt->m_fdinfo) &&
			!evt->m_fdinfo->is_udp_socket())
	{
		//
		// Mark this fd as a transaction
		//
		if(evt->m_fdinfo->m_usrstate == NULL)
		{
			evt->m_fdinfo->m_usrstate = new sinsp_partial_transaction();
		}

		if(family == PPM_AF_INET)
		{
			add_client_ipv4_connection(evt);
		}
	}
	else if(family == PPM_AF_UNIX)
	{
		m_inspector->m_parser->set_unix_info(evt->m_fdinfo, packed_data);
	}

	//
	// Baseline update
	//
	ASSERT(m_analyzer->m_falco_baseliner != NULL);

	// We only do baseline calculatation if the agent's resource usage is low 
	if(m_analyzer->m_do_baseline_calculation)
	{
		m_analyzer->m_falco_baseliner->on_connect(evt);
	}
}

void sinsp_analyzer_fd_listener::on_accept(sinsp_evt *evt, int64_t newfd, uint8_t* packed_data, sinsp_fdinfo_t* new_fdinfo)
{
	string scomm = evt->m_tinfo->get_comm();
	int64_t tid = evt->get_tid();

	//
	// Connection and transaction handling
	//
	if(new_fdinfo->m_type == SCAP_FD_IPV4_SOCK && should_report_network(new_fdinfo))
	{
		//
		// Add the tuple to the connection table
		//
		m_analyzer->m_ipv4_connections->add_connection(new_fdinfo->m_sockinfo.m_ipv4info,
			&scomm,
			evt->m_tinfo->m_pid,
		    tid,
		    newfd,
		    false,
		    evt->get_ts(),
		    sinsp_connection::AF_NONE,
		    0);
	}
	else if(new_fdinfo->m_type == SCAP_FD_UNIX_SOCK)
	{
		goto blupdate;
	}
	else if(new_fdinfo->m_type == SCAP_FD_UNINITIALIZED)
	{
		ASSERT(false);
		goto blupdate;
	}

	//
	// Mark this fd as a transaction
	//
	if(new_fdinfo->m_usrstate == NULL)
	{
		new_fdinfo->m_usrstate = new sinsp_partial_transaction();
	}

blupdate:
	//
	// Baseline update
	//
	ASSERT(m_analyzer->m_falco_baseliner != NULL);

	// We only do baseline calculatation if the agent's resource usage is low 
	if(m_analyzer->m_do_baseline_calculation)
	{
		m_analyzer->m_falco_baseliner->on_accept(evt, new_fdinfo);
	}
}

inline void sinsp_analyzer_fd_listener::flush_transaction(erase_fd_params* params)
{
	//
	// If this fd has an active transaction transaction table, mark it as unititialized
	//
	sinsp_connection *connection = nullptr;
	if(params->m_fdinfo->m_usrstate->is_active() && params->m_fdinfo->is_ipv4_socket())
	{
		connection = params->m_inspector->m_analyzer->get_connection(params->m_fdinfo->m_sockinfo.m_ipv4info, params->m_ts);
	}

	if(connection)
	{
		params->m_fdinfo->m_usrstate->update(params->m_inspector->m_analyzer,
			params->m_tinfo,
			params->m_fdinfo,
			connection,
			params->m_ts, 
			params->m_ts, 
			-1,
			sinsp_partial_transaction::DIR_CLOSE,
#if _DEBUG
			NULL,
			params->m_fd,
#endif
			NULL,
			0,
			0);
	}
}

void sinsp_analyzer_fd_listener::on_erase_fd(erase_fd_params* params)
{
	//
	// If this socket was cloned and it's still present on the parent, don't do anything
	//
	if(params->m_fdinfo->is_cloned() && (params->m_fdinfo->is_ipv4_socket() || params->m_fdinfo->is_ipv6_socket()))
	{
		sinsp_threadinfo *ptinfo = params->m_tinfo->get_parent_thread();
		if(ptinfo)
		{
			sinsp_fdinfo_t *pfdinfo = ptinfo->get_fd(params->m_fd);
			if(pfdinfo &&
			   pfdinfo->m_type == params->m_fdinfo->m_type &&
			   pfdinfo->m_name == params->m_fdinfo->m_name)
			{
				return;
			}
		}
	}

	//
	// If this fd has an active transaction transaction table, mark it as unititialized
	//
	if(params->m_fdinfo->is_transaction())
	{
		flush_transaction(params);
		params->m_fdinfo->m_usrstate->mark_inactive();
	}

	//
	// If the fd is in the connection table, schedule the connection for removal
	//
	if(params->m_fdinfo->is_ipv4_socket() && !params->m_fdinfo->has_no_role())
	{
		params->m_inspector->m_analyzer->m_ipv4_connections->remove_connection(params->m_fdinfo->m_sockinfo.m_ipv4info);
	}
}

void sinsp_analyzer_fd_listener::on_socket_shutdown(sinsp_evt *evt)
{
	//
	// If this fd has an active transaction, update it and then mark it as unititialized
	//
	if(evt->m_fdinfo->is_transaction() && evt->m_fdinfo->m_usrstate->is_active())
	{
		sinsp_connection* connection = NULL;

		if(evt->m_fdinfo->is_ipv4_socket())
		{
			connection = m_analyzer->get_connection(evt->m_fdinfo->m_sockinfo.m_ipv4info, evt->get_ts());
		}

		evt->m_fdinfo->m_usrstate->update(m_inspector->m_analyzer,
			evt->m_tinfo,
			evt->m_fdinfo,
			connection,
			evt->get_ts(), 
			evt->get_ts(), 
			evt->get_cpuid(),
			sinsp_partial_transaction::DIR_CLOSE,
#if _DEBUG
			evt,
			evt->m_tinfo->m_lastevent_fd,
#endif
			NULL,
			0,
			0);

		evt->m_fdinfo->m_usrstate->mark_inactive();
	}
}

void sinsp_analyzer_fd_listener::on_file_open(sinsp_evt* evt, const string& fullpath, uint32_t flags)
{
	//
	// File open count update
	//
	analyzer_file_stat* file_stat = get_file_stat(evt->get_thread_info(), fullpath);
	if(evt->m_fdinfo && evt->m_errorcode == 0)
	{
		ASSERT(evt->m_fdinfo->is_file());
		ASSERT(evt->m_fdinfo->m_name == fullpath);
		if(evt->m_fdinfo->is_file())
		{
			if(file_stat)
			{
				++file_stat->m_open_count;			
			}
		}
	}
	else
	{
		if(file_stat)
		{
			++file_stat->m_errors;
		}		
	}

	//
	// Baseline update
	//
	ASSERT(m_analyzer->m_falco_baseliner != NULL);

	// We only do baseline calculatation if the agent's resource usage is low 
	if(m_analyzer->m_do_baseline_calculation)
	{
		m_analyzer->m_falco_baseliner->on_file_open(evt, (string&)fullpath, flags);
	}
}


void sinsp_analyzer_fd_listener::on_socket_status_changed(sinsp_evt *evt)
{
	ASSERT(evt->m_fdinfo);

	if (evt->m_fdinfo->is_ipv4_socket() && evt->m_errorcode != EAGAIN)
	{
		auto connection = m_analyzer->get_connection(evt->m_fdinfo->m_sockinfo.m_ipv4info, evt->get_ts());
		if (connection)
		{
			connection->set_state(-evt->m_errorcode);
		}
	}
}

void sinsp_analyzer_fd_listener::on_error(sinsp_evt* evt)
{
	ASSERT(evt->m_fdinfo);
	ASSERT(evt->m_errorcode != 0);

	if(evt->m_fdinfo)
	{
		if(evt->m_fdinfo->is_file())
		{
			analyzer_file_stat* file_stat = get_file_stat(evt->get_thread_info(), evt->m_fdinfo->m_name);
			if(file_stat)
			{
				++file_stat->m_errors;
			}
		}
		else if(evt->m_fdinfo->is_transaction())
		{
			//
			// This attempts to flush a transaction when a read timeout happens.
			//
			erase_fd_params params;

			params.m_fdinfo = evt->m_fdinfo;
			params.m_tinfo = evt->m_tinfo;
			params.m_inspector = m_inspector;
			params.m_ts = evt->get_ts();
			params.m_fd = 0;
			enum ppm_event_category ecat = evt->m_info->category;

			//
			// We flush transaction if the I/O operation satisfies one of the 
			// following conditions:
			//  - the FD is a server one, this a failed read AND it's the first read after a bunch of writes 
			//  - the FD is a client one, this a failed write AND it's the first read after a bunch of reads 
			// In other words, we try to capture the attempt at beginning a new transaction, even if it
			// fails because there's no data yet.
			//
			if((params.m_fdinfo->is_role_server() && params.m_fdinfo->m_usrstate->m_direction == sinsp_partial_transaction::DIR_OUT && ecat == EC_IO_READ) ||
				(params.m_fdinfo->is_role_client() && params.m_fdinfo->m_usrstate->m_direction == sinsp_partial_transaction::DIR_IN && ecat == EC_IO_WRITE))
			{
				flush_transaction(&params);
			}
		}

		if (m_inspector->m_parser->m_track_connection_status)
		{
			on_socket_status_changed(evt);
		}
	}
}

void sinsp_analyzer_fd_listener::on_execve(sinsp_evt *evt)
{
	//
	// Baseline update
	//
	ASSERT(m_analyzer->m_falco_baseliner != NULL);

	// We only do baseline calculatation if the agent's resource usage is low 
	if(m_analyzer->m_do_baseline_calculation)
	{
		m_analyzer->m_falco_baseliner->on_new_proc(evt, evt->get_thread_info());
	}

	if (m_analyzer->m_track_environment) {
		auto tinfo = evt->get_thread_info();
		if (tinfo && tinfo->m_ainfo) {
			tinfo->m_ainfo->main_thread_ainfo()->hash_environment(tinfo, *m_analyzer->m_env_hash_config.m_env_blacklist);
		}
	}
}

void sinsp_analyzer_fd_listener::on_bind(sinsp_evt *evt)
{
	//
	// Baseline update
	//
	ASSERT(m_analyzer->m_falco_baseliner != NULL);

	// We only do baseline calculatation if the agent's resource usage is low 
	if(m_analyzer->m_do_baseline_calculation)
	{
		m_analyzer->m_falco_baseliner->on_bind(evt);
	}
}

bool sinsp_analyzer_fd_listener::on_resolve_container(sinsp_container_manager* manager, sinsp_threadinfo* tinfo, bool query_os_for_missing_info)
{
#ifndef CYGWING_AGENT
	return m_analyzer->m_custom_container.resolve(manager, tinfo, query_os_for_missing_info);
#else
	return false;
#endif
}

void sinsp_analyzer_fd_listener::on_clone(sinsp_evt *evt, sinsp_threadinfo* newtinfo)
{
	//
	// Baseline update
	//
	ASSERT(m_analyzer->m_falco_baseliner != NULL);

	// We only do baseline calculatation if the agent's resource usage is low 
	if(m_analyzer->m_do_baseline_calculation)
	{
		m_analyzer->m_falco_baseliner->on_new_proc(evt, newtinfo);
	}
}

analyzer_file_stat* sinsp_analyzer_fd_listener::get_file_stat(const sinsp_threadinfo* tinfo, const string& name)
{
#if defined(HAS_CAPTURE)
	//
	// Exclude dragent files to be consistent with everything else
	//
	if(tinfo->m_pid == m_inspector->m_sysdig_pid)
	{
		return NULL;
	}
#endif

	unordered_map<string, analyzer_file_stat>::iterator it = 
		m_files_stat.find(name);

	if(it == m_files_stat.end())
	{
		analyzer_file_stat file_stat;
		file_stat.m_name = name;
		m_files_stat.insert(pair<string, analyzer_file_stat>(string(name), file_stat));
		it = m_files_stat.find(name);
	}

	return &it->second;
}

bool sinsp_analyzer_fd_listener::should_report_network(sinsp_fdinfo_t *fdinfo)
{
	return !m_sinsp_config->get_blacklisted_ports().test(fdinfo->get_serverport());
}
#endif // HAS_ANALYZER
