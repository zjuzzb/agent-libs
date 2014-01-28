#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

#include "../../driver/ppm_ringbuffer.h"
#include "sinsp.h"
#include "sinsp_int.h"

#ifdef HAS_ANALYZER
#include "parsers.h"
#include "analyzer_int.h"
#include "analyzer.h"
#include "connectinfo.h"
#include "metrics.h"
#include "draios.pb.h"
#include "delays.h"
#include "scores.h"
#include "procfs_parser.h"
#include "sinsp_errno.h"
#include "sched_analyzer.h"
#include "analyzer_fd.h"

///////////////////////////////////////////////////////////////////////////////
// sinsp_percpu_delays implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_analyzer_fd_listener::sinsp_analyzer_fd_listener(sinsp* inspector, sinsp_analyzer* analyzer)
{
	m_inspector = inspector; 
	m_analyzer = analyzer;
}

void sinsp_analyzer_fd_listener::on_read(sinsp_evt *evt, int64_t tid, int64_t fd, char *data, uint32_t original_len, uint32_t len)
{
	evt->set_iosize(original_len);

	if(evt->m_fdinfo->is_ipv4_socket() || evt->m_fdinfo->is_unix_socket())
	{
		sinsp_connection *connection = NULL;

		/////////////////////////////////////////////////////////////////////////////
		// Handle the connection
		/////////////////////////////////////////////////////////////////////////////
		if(evt->m_fdinfo->is_unix_socket())
		{
			// ignore invalid destination addresses
			if(0 == evt->m_fdinfo->m_sockinfo.m_unixinfo.m_fields.m_dest)
			{
				return;
			}

			connection = m_analyzer->get_connection(evt->m_fdinfo->m_sockinfo.m_unixinfo, evt->get_ts());
			if(connection == NULL)
			{
				//
				// We dropped the accept() or connect()
				// Create a connection entry here and make an assumption this is the server FD.
				// (we assume that a server usually starts with a read).
				//
				evt->m_fdinfo->set_role_server();
				string scomm = evt->m_tinfo->get_comm();
				connection = m_analyzer->m_unix_connections->add_connection(evt->m_fdinfo->m_sockinfo.m_unixinfo,
					&scomm,
					evt->m_tinfo->m_pid,
					tid,
					fd,
					evt->m_fdinfo->is_role_client(),
					evt->get_ts());
			}
			else if((!(evt->m_tinfo->m_pid == connection->m_spid && fd == connection->m_sfd) &&
				!(evt->m_tinfo->m_pid == connection->m_dpid && fd == connection->m_dfd)) ||
				(connection->m_analysis_flags & sinsp_connection::AF_CLOSED))
			{
				//
				// We dropped both accept() and connect(), and the connection has already been established
				// when handling a read on the other side.
				//
				if(connection->m_analysis_flags == sinsp_connection::AF_CLOSED)
				{
					//
					// There is a closed connection with the same key. We drop its content and reuse it.
					// We also mark it as reused so that the analyzer is aware of it
					//
					connection->reset();
					connection->m_analysis_flags = sinsp_connection::AF_REUSED;
					evt->m_fdinfo->set_role_server();
				}
				else
				{
					if(connection->is_server_only())
					{
						evt->m_fdinfo->set_role_client();
					}
					else if(connection->is_client_only())
					{
						evt->m_fdinfo->set_role_server();
					}
					else
					{
						//
						// FDs don't match but the connection has not been closed yet.
						// This seem to heppen with unix sockets, whose addresses are reused when 
						// just on of the endpoints has been closed.
						// Jusr recycle the connection.
						//
						if(evt->m_fdinfo->is_role_server())
						{
							connection->reset_server();
						}
						else if(evt->m_fdinfo->is_role_client())
						{
							connection->reset_client();
						}
						else
						{
							connection->reset();
						}

						connection->m_analysis_flags = sinsp_connection::AF_REUSED;
						evt->m_fdinfo->set_role_server();
					}
				}

				string scomm = evt->m_tinfo->get_comm();
				connection = m_analyzer->m_unix_connections->add_connection(evt->m_fdinfo->m_sockinfo.m_unixinfo,
					&scomm,
					evt->m_tinfo->m_pid,
					tid,
					fd,
					evt->m_fdinfo->is_role_client(),
					evt->get_ts());
			}
		}
		else if(evt->m_fdinfo->is_ipv4_socket())
		{
			connection = m_analyzer->get_connection(evt->m_fdinfo->m_sockinfo.m_ipv4info, evt->get_ts());
			
			if(connection == NULL)
			{
				//
				// We dropped the accept() or connect()
				// Create a connection entry here and try to detect if this is the client or the server by lookig
				// at the ports.
				//
				evt->m_fdinfo->set_role_by_guessing(true);

				string scomm = evt->m_tinfo->get_comm();
				
				connection = m_analyzer->m_ipv4_connections->add_connection(evt->m_fdinfo->m_sockinfo.m_ipv4info,
					&scomm,
					evt->m_tinfo->m_pid,
				    tid,
				    fd,
				    evt->m_fdinfo->is_role_client(),
				    evt->get_ts());
			}
			else if((!(evt->m_tinfo->m_pid == connection->m_spid && fd == connection->m_sfd) &&
				!(evt->m_tinfo->m_pid == connection->m_dpid && fd == connection->m_dfd)) ||
				(connection->m_analysis_flags & sinsp_connection::AF_CLOSED))
			{
				//
				// We dropped both accept() and connect(), and the connection has already been established
				// when handling a read on the other side.
				//
				if(connection->m_analysis_flags == sinsp_connection::AF_CLOSED)
				{
					//
					// There is a closed connection with the same key. We drop its content and reuse it.
					// We also mark it as reused so that the analyzer is aware of it
					//
					connection->reset();
					connection->m_analysis_flags = sinsp_connection::AF_REUSED;
					evt->m_fdinfo->set_role_by_guessing(true);
				}
				else
				{
					if(connection->is_server_only())
					{
						evt->m_fdinfo->set_role_client();
					}
					else if(connection->is_client_only())
					{
						evt->m_fdinfo->set_role_server();
					}
					else
					{
						//
						// FDs don't match but the connection has not been closed yet.
						// This can happen in case of event drops, or when a commection
						// is accepted by a process and served by another one.
						//
						if(evt->m_fdinfo->is_role_server())
						{
							connection->reset_server();
						}
						else if(evt->m_fdinfo->is_role_client())
						{
							connection->reset_client();
						}
						else
						{
							connection->reset();
						}

						connection->m_analysis_flags = sinsp_connection::AF_REUSED;
						evt->m_fdinfo->set_role_by_guessing(true);
					}
				}

				string scomm = evt->m_tinfo->get_comm();
				connection = m_analyzer->m_ipv4_connections->add_connection(evt->m_fdinfo->m_sockinfo.m_ipv4info,
					&scomm,
					evt->m_tinfo->m_pid,
					tid,
					fd,
					evt->m_fdinfo->is_role_client(),
					evt->get_ts());
			}
		}

		//
		// Attribute the read bytes to the proper connection side
		//
		if(connection == NULL)
		{
			//
			// This happens when the connection table is full
			//
			return;
		}

		if(evt->m_fdinfo->is_role_server())
		{
			connection->m_metrics.m_server.add_in(1, original_len);
		}
		else if (evt->m_fdinfo->is_role_client())
		{
			connection->m_metrics.m_client.add_in(1, original_len);
		}
		else
		{
			ASSERT(false);
		}

		/////////////////////////////////////////////////////////////////////////////
		// Handle the transaction
		/////////////////////////////////////////////////////////////////////////////
/*
		if(evt->m_fdinfo->is_role_server())
		{
			//
			// See if there's already a transaction
			//
 			sinsp_partial_transaction *trinfo = &(evt->m_fdinfo->m_usrstate);
			if(trinfo->m_type == sinsp_partial_transaction::TYPE_UNKNOWN)
			{
				//
				// Try to parse this as HTTP
				//
				if(m_http_parser.is_msg_http(data, len) && m_http_parser.parse_request(data, len))
				{
					//
					// Success. Add an HTTP entry to the transaction table for this fd
					//
					trinfo->m_type = sinsp_partial_transaction::TYPE_HTTP;
					trinfo->m_protoinfo.push_back(m_http_parser.m_url);
					trinfo->m_protoinfo.push_back(m_http_parser.m_agent);
				}
				else
				{
					//
					// The message has not been recognized as HTTP.
					// Add an IP entry to the transaction table for this fd
					//
					trinfo->m_type = sinsp_partial_transaction::TYPE_IP;
				}
			}

			//
			// Update the transaction state.
			//
			ASSERT(connection != NULL);
			trinfo->update(m_analyzer,
				evt->m_tinfo,
				connection,
				evt->m_tinfo->m_lastevent_ts, 
				evt->get_ts(), 
				sinsp_partial_transaction::DIR_IN, 
				len);
		}
*/

		//
		// See if there's already a transaction
		//
 		sinsp_partial_transaction *trinfo = &(evt->m_fdinfo->m_usrstate);
		if(!trinfo->is_active())
		{
			//
			// New transaction. Just mark it as IP, which is the only kind of transaction we support for the moment.
			//
			trinfo->mark_active_and_reset(sinsp_partial_transaction::TYPE_IP);
			evt->m_fdinfo->set_is_transaction();
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

		//
		// Update the transaction state.
		//
		trinfo->update(m_analyzer,
			evt->m_tinfo,
			evt->m_fdinfo,
			connection,
			evt->m_tinfo->m_lastevent_ts, 
			evt->get_ts(), 
			evt->get_cpuid(),
			trdir, 
			len);
	}
	else if(evt->m_fdinfo->is_pipe())
	{
		sinsp_connection *connection = m_analyzer->get_connection(evt->m_fdinfo->m_ino, evt->get_ts());
		if(NULL == connection || connection->is_server_only())
		{
			string scomm = evt->m_tinfo->get_comm();
			m_analyzer->m_pipe_connections->add_connection(evt->m_fdinfo->m_ino,
				&scomm,
				evt->m_tinfo->m_pid,
			    tid,
			    fd,
			    true,
			    evt->get_ts());
		}
	}
}

void sinsp_analyzer_fd_listener::on_write(sinsp_evt *evt, int64_t tid, int64_t fd, char *data, uint32_t original_len, uint32_t len)
{
	evt->set_iosize(original_len);

	if(evt->m_fdinfo->is_ipv4_socket() || evt->m_fdinfo->is_unix_socket())
	{
		/////////////////////////////////////////////////////////////////////////////
		// Handle the connection
		/////////////////////////////////////////////////////////////////////////////
		sinsp_connection *connection = NULL; 

		if(evt->m_fdinfo->is_unix_socket())
		{
			// ignore invalid destination addresses
			if(0 == evt->m_fdinfo->m_sockinfo.m_unixinfo.m_fields.m_dest)
			{
				return;
			}

			connection = m_analyzer->get_connection(evt->m_fdinfo->m_sockinfo.m_unixinfo, evt->get_ts());
			if(connection == NULL)
			{
				//
				// We dropped the accept() or connect()
				// Create a connection entry here and make an assumption this is the client FD
				// (we assume that a client usually starts with a write)
				//
				evt->m_fdinfo->set_role_client();
				string scomm = evt->m_tinfo->get_comm();
				connection = m_analyzer->m_unix_connections->add_connection(evt->m_fdinfo->m_sockinfo.m_unixinfo,
					&scomm,
					evt->m_tinfo->m_pid,
				    tid,
				    fd,
				    evt->m_fdinfo->is_role_client(),
				    evt->get_ts());
			}
			else if(!(evt->m_tinfo->m_pid == connection->m_spid && fd == connection->m_sfd) &&
				!(evt->m_tinfo->m_pid == connection->m_dpid && fd == connection->m_dfd))
			{
				//
				// We dropped both accept() and connect(), and the connection has already been established
				// when handling a read on the other side.
				//
				if(connection->m_analysis_flags == sinsp_connection::AF_CLOSED)
				{
					//
					// There is a closed connection with the same key. We drop its content and reuse it.
					// We also mark it as reused so that the analyzer is aware of it
					//
					connection->reset();
					connection->m_analysis_flags = sinsp_connection::AF_REUSED;
					evt->m_fdinfo->set_role_client();
				}
				else
				{
					if(connection->is_server_only())
					{
						evt->m_fdinfo->set_role_client();
					}
					else if(connection->is_client_only())
					{
						evt->m_fdinfo->set_role_server();
					}
					else
					{
						//
						// FDs don't match but the connection has not been closed yet.
						// This seem to heppen with unix sockets, whose addresses are reused when 
						// just on of the endpoints has been closed.
						// Jusr recycle the connection.
						//
						if(evt->m_fdinfo->is_role_server())
						{
							connection->reset_server();
						}
						else if(evt->m_fdinfo->is_role_client())
						{
							connection->reset_client();
						}
						else
						{
							connection->reset();
						}

						connection->m_analysis_flags = sinsp_connection::AF_REUSED;
						evt->m_fdinfo->set_role_client();
					}
				}

				string scomm = evt->m_tinfo->get_comm();
				connection = m_analyzer->m_unix_connections->add_connection(evt->m_fdinfo->m_sockinfo.m_unixinfo,
					&scomm,
					evt->m_tinfo->m_pid,
					tid,
					fd,
					evt->m_fdinfo->is_role_client(),
					evt->get_ts());
			}
		}
		else if(evt->m_fdinfo->is_ipv4_socket())
		{
			connection = m_analyzer->get_connection(evt->m_fdinfo->m_sockinfo.m_ipv4info, evt->get_ts());

			if(connection == NULL)
			{
				//
				// We dropped the accept() or connect()
				// Create a connection entry here and try to detect if this is the client or the server by lookig
				// at the ports.
				// (we assume that a client usually starts with a write)
				//
				evt->m_fdinfo->set_role_by_guessing(false);
				string scomm = evt->m_tinfo->get_comm();
				connection = m_analyzer->m_ipv4_connections->add_connection(evt->m_fdinfo->m_sockinfo.m_ipv4info,
					&scomm,
					evt->m_tinfo->m_pid,
				    tid,
				    fd,
				    evt->m_fdinfo->is_role_client(),
				    evt->get_ts());
			}
			else if(!(evt->m_tinfo->m_pid == connection->m_spid && fd == connection->m_sfd) &&
				!(evt->m_tinfo->m_pid == connection->m_dpid && fd == connection->m_dfd))
			{
				//
				// We dropped both accept() and connect(), and the connection has already been established
				// when handling a read on the other side.
				//
				if(connection->m_analysis_flags == sinsp_connection::AF_CLOSED)
				{
					//
					// There is a closed connection with the same key. We drop its content and reuse it.
					// We also mark it as reused so that the analyzer is aware of it
					//
					connection->reset();
					connection->m_analysis_flags = sinsp_connection::AF_REUSED;
					evt->m_fdinfo->set_role_by_guessing(false);
				}
				else
				{
					if(connection->is_server_only())
					{
						evt->m_fdinfo->set_role_client();
					}
					else if(connection->is_client_only())
					{
						evt->m_fdinfo->set_role_server();
					}
					else
					{
						//
						// FDs don't match but the connection has not been closed yet.
						// This can happen in case of event drops, or when a commection
						// is accepted by a process and served by another one.
						//
						if(evt->m_fdinfo->is_role_server())
						{
							connection->reset_server();
						}
						else if(evt->m_fdinfo->is_role_client())
						{
							connection->reset_client();
						}
						else
						{
							connection->reset();
						}

						connection->m_analysis_flags = sinsp_connection::AF_REUSED;
						evt->m_fdinfo->set_role_by_guessing(false);
					}
				}

				string scomm = evt->m_tinfo->get_comm();
				connection = m_analyzer->m_ipv4_connections->add_connection(evt->m_fdinfo->m_sockinfo.m_ipv4info,
					&scomm,
					evt->m_tinfo->m_pid,
					tid,
					fd,
					evt->m_fdinfo->is_role_client(),
					evt->get_ts());
			}
		}

		//
		// Attribute the read bytes to the proper connection side
		//
		if(connection == NULL)
		{
			//
			// This happens when the connection table is full
			//
			return;
		}

		if(evt->m_fdinfo->is_role_server())
		{
			connection->m_metrics.m_server.add_out(1, original_len);
		}
		else if(evt->m_fdinfo->is_role_client())
		{
			connection->m_metrics.m_client.add_out(1, original_len);
		}
		else
		{
			ASSERT(false);
		}

		/////////////////////////////////////////////////////////////////////////////
		// Handle the transaction
		/////////////////////////////////////////////////////////////////////////////
		//
		// See if there's already a transaction
		//
 		sinsp_partial_transaction *trinfo = &(evt->m_fdinfo->m_usrstate);
		if(!trinfo->is_active())
		{
			//
			// New transaction. Just mark it as IP, which is the only kind of transaction we support for the moment.
			//
			trinfo->mark_active_and_reset(sinsp_partial_transaction::TYPE_IP);
			evt->m_fdinfo->set_is_transaction();
		}

		//
		// Update the transaction state.
		//
		trinfo->update(m_analyzer,
			evt->m_tinfo,
			evt->m_fdinfo,
			connection,
			evt->m_tinfo->m_lastevent_ts, 
			evt->get_ts(), 
			evt->get_cpuid(),
			sinsp_partial_transaction::DIR_OUT, 
			len);
	}
	else if(evt->m_fdinfo->is_pipe())
	{
		sinsp_connection *connection = m_analyzer->get_connection(evt->m_fdinfo->m_ino, evt->get_ts());

		if(NULL == connection || connection->is_client_only())
		{
			string scomm = evt->m_tinfo->get_comm();
			m_analyzer->m_pipe_connections->add_connection(evt->m_fdinfo->m_ino,
				&scomm,
				evt->m_tinfo->m_pid,
			    tid,
			    fd,
			    false,
			    evt->get_ts());
		}
	}
}

void sinsp_analyzer_fd_listener::on_connect(sinsp_evt *evt, uint8_t* packed_data)
{
	int64_t tid = evt->get_tid();

	uint8_t family = *packed_data;

	if(family == PPM_AF_INET || family == PPM_AF_INET6)
	{
		//
		// Mark this fd as a client
		//
		evt->m_fdinfo->set_role_client();

		//
		// Mark this fd as a transaction
		//
		evt->m_fdinfo->set_is_transaction();

		//
		// Lookup the connection
		//
		sinsp_connection* conn = m_analyzer->m_ipv4_connections->get_connection(
			evt->m_fdinfo->m_sockinfo.m_ipv4info,
			evt->get_ts());

		//
		// If a connection for this tuple is already there, drop it and replace it with a new one.
		// Note that remove_connection just decreases the connection reference counter, since connections
		// are destroyed by the analyzer at the end of the sample.
		// Note that UDP sockets can have an arbitrary number of connects, and each new one overrides
		// the previous one.
		//
		if(conn)
		{
			if(conn->m_analysis_flags == sinsp_connection::AF_CLOSED)
			{
				//
				// There is a closed connection with the same key. We drop its content and reuse it.
				// We also mark it as reused so that the analyzer is aware of it
				//
				conn->reset();
				conn->m_analysis_flags = sinsp_connection::AF_REUSED;
				conn->m_refcount = 1;
			}

			m_analyzer->m_ipv4_connections->remove_connection(evt->m_fdinfo->m_sockinfo.m_ipv4info);
		}

		//
		// Update the FD info with this tuple
		//
		if(family == PPM_AF_INET)
		{
			m_inspector->m_parser->set_ipv4_addresses_and_ports(evt->m_fdinfo, packed_data);
		}
		else
		{
			m_inspector->m_parser->set_ipv4_mapped_ipv6_addresses_and_ports(evt->m_fdinfo, packed_data);
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
		    evt->get_ts());
	}
	else
	{
		//
		// Mark this fd as a client
		//
		evt->m_fdinfo->set_role_client();

		//
		// Mark this fd as a transaction
		//
		evt->m_fdinfo->set_is_transaction();

		m_inspector->m_parser->set_unix_info(evt->m_fdinfo, packed_data);

		string scomm = evt->m_tinfo->get_comm();
		m_analyzer->m_unix_connections->add_connection(evt->m_fdinfo->m_sockinfo.m_unixinfo,
			&scomm,
			evt->m_tinfo->m_pid,
		    tid,
		    evt->m_tinfo->m_lastevent_fd,
		    true,
		    evt->get_ts());
	}
}

void sinsp_analyzer_fd_listener::on_accept(sinsp_evt *evt, int64_t newfd, uint8_t* packed_data, sinsp_fdinfo_t* new_fdinfo)
{
	string scomm = evt->m_tinfo->get_comm();
	int64_t tid = evt->get_tid();

	if(new_fdinfo->m_type == SCAP_FD_IPV4_SOCK)
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
		    evt->get_ts());
	}
	else if(new_fdinfo->m_type == SCAP_FD_UNIX_SOCK)
	{
		m_analyzer->m_unix_connections->add_connection(new_fdinfo->m_sockinfo.m_unixinfo,
			&scomm,
			evt->m_tinfo->m_pid,
		    tid,
		    newfd,
		    false,
		    evt->get_ts());
	}
	else
	{
		//
		// This should be checked by parse_accept_exit()
		//
		ASSERT(false);
	}

	//
	// Mark this fd as a server
	//
	new_fdinfo->set_role_server();

	//
	// Mark this fd as a transaction
	//
	new_fdinfo->set_is_transaction();
}

void sinsp_analyzer_fd_listener::on_erase_fd(erase_fd_params* params)
{
	//
	// If this fd has an active transaction transaction table, mark it as unititialized
	//
	if(params->m_fdinfo->is_transaction())
	{
		sinsp_connection *connection;
		bool do_remove_transaction = params->m_fdinfo->m_usrstate.is_active();

		if(do_remove_transaction)
		{
			if(params->m_fdinfo->is_ipv4_socket())
			{
				connection = params->m_inspector->m_analyzer->get_connection(params->m_fdinfo->m_sockinfo.m_ipv4info, 
					params->m_ts);
			}
			else if(params->m_fdinfo->is_unix_socket())
			{
				connection = params->m_inspector->m_analyzer->get_connection(params->m_fdinfo->m_sockinfo.m_unixinfo, 
					params->m_ts);
			}
			else
			{
				ASSERT(false);
				do_remove_transaction = false;
			}
		}

		if(do_remove_transaction)
		{
			params->m_fdinfo->m_usrstate.update(params->m_inspector->m_analyzer,
				params->m_tinfo,
				params->m_fdinfo,
				connection,
				params->m_ts, 
				params->m_ts, 
				-1,
				sinsp_partial_transaction::DIR_CLOSE,
				0);
		}

		params->m_fdinfo->m_usrstate.mark_inactive();			
	}

	//
	// If the fd is in the connection table, schedule the connection for removal
	//
	if(params->m_fdinfo->is_ipv4_socket() && 
		!params->m_fdinfo->has_no_role())
	{
		params->m_inspector->m_analyzer->m_ipv4_connections->remove_connection(params->m_fdinfo->m_sockinfo.m_ipv4info, false);
	}
	else if(params->m_fdinfo->is_unix_socket() && 
		!params->m_fdinfo->has_no_role())
	{
		params->m_inspector->m_analyzer->m_unix_connections->remove_connection(params->m_fdinfo->m_sockinfo.m_unixinfo, false);
	}
}

void sinsp_analyzer_fd_listener::on_socket_shutdown(sinsp_evt *evt)
{
	//
	// If this fd has an active transaction, update it and then mark it as unititialized
	//
	if(evt->m_fdinfo->m_usrstate.is_active())
	{
		sinsp_connection* connection;

		if(evt->m_fdinfo->is_ipv4_socket())
		{
			connection = m_analyzer->get_connection(evt->m_fdinfo->m_sockinfo.m_ipv4info, evt->get_ts());
		}
		else
		{
			connection = m_analyzer->get_connection(evt->m_fdinfo->m_sockinfo.m_unixinfo, evt->get_ts());
		}

		evt->m_fdinfo->m_usrstate.update(m_inspector->m_analyzer,
			evt->m_tinfo,
			evt->m_fdinfo,
			connection,
			evt->get_ts(), 
			evt->get_ts(), 
			evt->get_cpuid(),
			sinsp_partial_transaction::DIR_CLOSE, 
			0);

		evt->m_fdinfo->m_usrstate.mark_inactive();
	}
}

#endif // HAS_ANALYZER
