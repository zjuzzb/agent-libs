#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

#include "../../driver/ppm_ringbuffer.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "parsers.h"
#include "connectinfo.h"
#include "metrics.h"
#include "analyzer.h"
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
sinsp_analyzer_rw_listener::sinsp_analyzer_rw_listener(sinsp* inspector, sinsp_analyzer* analyzer)
{
	m_inspector = inspector; 
	m_analyzer = analyzer;
}

void sinsp_analyzer_rw_listener::on_read(sinsp_evt *evt, int64_t tid, int64_t fd, char *data, uint32_t original_len, uint32_t len)
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
			if(0 == evt->m_fdinfo->m_info.m_unixinfo.m_fields.m_dest)
			{
				return;
			}

			connection = m_inspector->get_connection(evt->m_fdinfo->m_info.m_unixinfo, evt->get_ts());
			if(connection == NULL)
			{
				//
				// We dropped the accept() or connect()
				// Create a connection entry here and make an assumption this is the server FD.
				// (we assume that a server usually starts with a read).
				//
				evt->m_fdinfo->set_role_server();
				string scomm = evt->m_tinfo->get_comm();
				connection = m_inspector->m_unix_connections->add_connection(evt->m_fdinfo->m_info.m_unixinfo,
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
						connection->reset();
						connection->m_analysis_flags = sinsp_connection::AF_REUSED;
						evt->m_fdinfo->set_role_server();
					}
				}

				string scomm = evt->m_tinfo->get_comm();
				connection = m_inspector->m_unix_connections->add_connection(evt->m_fdinfo->m_info.m_unixinfo,
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
			connection = m_inspector->get_connection(evt->m_fdinfo->m_info.m_ipv4info, evt->get_ts());
			
			if(connection == NULL)
			{
				//
				// We dropped the accept() or connect()
				// Create a connection entry here and try to detect if this is the client or the server by lookig
				// at the ports.
				//
				evt->m_fdinfo->set_role_by_guessing(sinsp_partial_transaction::DIR_IN);

				string scomm = evt->m_tinfo->get_comm();
				
				connection = m_inspector->m_ipv4_connections->add_connection(evt->m_fdinfo->m_info.m_ipv4info,
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
					evt->m_fdinfo->set_role_by_guessing(sinsp_partial_transaction::DIR_IN);
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
						// This can happen in case of event drops.
						//
						connection->reset();
						connection->m_analysis_flags = sinsp_connection::AF_REUSED;
						evt->m_fdinfo->set_role_by_guessing(sinsp_partial_transaction::DIR_IN);
					}
				}

				string scomm = evt->m_tinfo->get_comm();
				connection = m_inspector->m_ipv4_connections->add_connection(evt->m_fdinfo->m_info.m_ipv4info,
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
			trinfo->update(m_inspector,
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
		trinfo->update(m_inspector,
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
		sinsp_connection *connection = m_inspector->get_connection(evt->m_fdinfo->m_ino, evt->get_ts());
		if(NULL == connection || connection->is_server_only())
		{
			string scomm = evt->m_tinfo->get_comm();
			m_inspector->m_pipe_connections->add_connection(evt->m_fdinfo->m_ino,
				&scomm,
				evt->m_tinfo->m_pid,
			    tid,
			    fd,
			    true,
			    evt->get_ts());
		}
	}
}

void sinsp_analyzer_rw_listener::on_write(sinsp_evt *evt, int64_t tid, int64_t fd, char *data, uint32_t original_len, uint32_t len)
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
			if(0 == evt->m_fdinfo->m_info.m_unixinfo.m_fields.m_dest)
			{
				return;
			}

			connection = m_inspector->get_connection(evt->m_fdinfo->m_info.m_unixinfo, evt->get_ts());
			if(connection == NULL)
			{
				//
				// We dropped the accept() or connect()
				// Create a connection entry here and make an assumption this is the client FD
				// (we assume that a client usually starts with a write)
				//
				evt->m_fdinfo->set_role_client();
				string scomm = evt->m_tinfo->get_comm();
				connection = m_inspector->m_unix_connections->add_connection(evt->m_fdinfo->m_info.m_unixinfo,
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
						connection->reset();
						connection->m_analysis_flags = sinsp_connection::AF_REUSED;
						evt->m_fdinfo->set_role_client();
					}
				}

				string scomm = evt->m_tinfo->get_comm();
				connection = m_inspector->m_unix_connections->add_connection(evt->m_fdinfo->m_info.m_unixinfo,
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
			connection = m_inspector->get_connection(evt->m_fdinfo->m_info.m_ipv4info, evt->get_ts());

			if(connection == NULL)
			{
				//
				// We dropped the accept() or connect()
				// Create a connection entry here and try to detect if this is the client or the server by lookig
				// at the ports.
				// (we assume that a client usually starts with a write)
				//
				evt->m_fdinfo->set_role_by_guessing(sinsp_partial_transaction::DIR_OUT);
				string scomm = evt->m_tinfo->get_comm();
				connection = m_inspector->m_ipv4_connections->add_connection(evt->m_fdinfo->m_info.m_ipv4info,
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
					evt->m_fdinfo->set_role_by_guessing(sinsp_partial_transaction::DIR_OUT);
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
						// This can happen in case of event drops.
						//
						connection->reset();
						connection->m_analysis_flags = sinsp_connection::AF_REUSED;
						evt->m_fdinfo->set_role_by_guessing(sinsp_partial_transaction::DIR_OUT);
					}
				}

				string scomm = evt->m_tinfo->get_comm();
				connection = m_inspector->m_ipv4_connections->add_connection(evt->m_fdinfo->m_info.m_ipv4info,
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
		trinfo->update(m_inspector,
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
		sinsp_connection *connection = m_inspector->get_connection(evt->m_fdinfo->m_ino, evt->get_ts());

		if(NULL == connection || connection->is_client_only())
		{
			string scomm = evt->m_tinfo->get_comm();
			m_inspector->m_pipe_connections->add_connection(evt->m_fdinfo->m_ino,
				&scomm,
				evt->m_tinfo->m_pid,
			    tid,
			    fd,
			    false,
			    evt->get_ts());
		}
	}
}
