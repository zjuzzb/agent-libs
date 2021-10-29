#include "analyzer_fd.h"

#include "analyzer.h"
#include "analyzer_int.h"
#include "analyzer_thread.h"
#include "baseliner.h"
#include "configuration_manager.h"
#include "connectinfo.h"
#include "delays.h"
#include "draios.pb.h"
#include "metrics.h"
#include "parsers.h"
#include "procfs_parser.h"
#include "protocol_manager.h"
#include "sched_analyzer.h"
#include "scores.h"
#include "sinsp.h"
#include "sinsp_errno.h"
#include "sinsp_int.h"
#include "statsite_config.h"
#include "statsite_proxy.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

using namespace libsanalyzer;

namespace
{
COMMON_LOGGER();

port_list_config c_blacklisted_ports("list of ports that we do not report on", "blacklisted_ports");

}  // end namespace

///////////////////////////////////////////////////////////////////////////////
// sinsp_analyzer_fd_listener implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_analyzer_fd_listener::sinsp_analyzer_fd_listener(sinsp* const inspector,
                                                       sinsp_analyzer* const analyzer,
                                                       sinsp_baseliner* const falco_baseliner)
    : m_inspector(inspector),
      m_analyzer(analyzer),
      m_falco_baseliner(falco_baseliner)
{
}

bool sinsp_analyzer_fd_listener::patch_network_role(thread_analyzer_info* ptinfo,
                                                    sinsp_fdinfo_t* pfdinfo,
                                                    bool incoming)
{
	//
	// This should be disabled for the moment
	//
	ASSERT(false);

	bool is_sip_local = m_inspector->m_network_interfaces->is_ipv4addr_in_local_machine(
	    pfdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip,
	    ptinfo);
	bool is_dip_local = m_inspector->m_network_interfaces->is_ipv4addr_in_local_machine(
	    pfdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip,
	    ptinfo);

	//
	// If only the client is local, mark the role as client.
	// If only the server is local, mark the role as server.
	//
	if (is_sip_local && !is_dip_local)
	{
		pfdinfo->set_role_client();
		return true;
	}
	else if (is_dip_local && !is_sip_local)
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
	if (!ptinfo->is_bound_to_port(pfdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport))
	{
		pfdinfo->set_role_client();
		return true;
	}

	if (!ptinfo->uses_client_port(pfdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport))
	{
		pfdinfo->set_role_server();
		return true;
	}

	//
	// The process owns both the client and server port.
	// We just assume that a server usually starts with a read and a client with a write
	//
	if (!(pfdinfo->m_flags &
	      (sinsp_fdinfo_t::FLAGS_ROLE_CLIENT | sinsp_fdinfo_t::FLAGS_ROLE_SERVER)))
	{
		if (incoming)
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

sinsp_connection* sinsp_analyzer_fd_listener::get_ipv4_connection(sinsp_fdinfo_t* fdinfo,
                                                                  const ipv4tuple& tuple,
                                                                  sinsp_evt* evt,
                                                                  int64_t tid,
                                                                  int64_t fd,
                                                                  bool incoming)
{
	sinsp_connection* connection = m_analyzer->get_connection(tuple, evt->get_ts());

	if (connection == nullptr)
	{
		//
		// This is either:
		//  - the first read of a UDP socket
		//  - a TCP socket for which we dropped the accept() or connect()
		// Create a connection entry here and try to automatically detect if this is the client or
		// the server.
		//
		if (fdinfo->is_role_none() &&
		    !patch_network_role(thread_analyzer_info::get_thread_from_event(evt), fdinfo, incoming))
		{
			return nullptr;
		}
	}
	else if (connection->m_analysis_flags & sinsp_connection::AF_CLOSED)
	{
		//
		// There is a closed connection with the same key. We drop its content and reuse it.
		// We also mark it as reused so that the analyzer is aware of it
		//

		connection->reset();
		connection->m_analysis_flags = sinsp_connection::AF_REUSED;

		if (fdinfo->is_role_none() &&
		    !patch_network_role(thread_analyzer_info::get_thread_from_event(evt), fdinfo, incoming))
		{
			// XXX should we return connection (without adding it to the table???) or nullptr?
			// XXX how can we end up here?
			return connection;
		}
	}
	else if ((evt->m_tinfo->m_pid != connection->m_spid || fd != connection->m_sfd) &&
	         (evt->m_tinfo->m_pid != connection->m_dpid || fd != connection->m_dfd))
	{
		//
		// We dropped both accept() and connect(), and the connection has already been established
		// when handling a read on the other side.
		//
		if (connection->is_server_only())
		{
			if (fdinfo->is_role_none())
			{
				fdinfo->set_role_client();
			}
		}
		else if (connection->is_client_only())
		{
			if (fdinfo->is_role_none())
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
			if (fdinfo->is_role_server())
			{
				connection->reset_server();
			}
			else if (fdinfo->is_role_client())
			{
				connection->reset_client();
			}
			else
			{
				connection->reset();
			}

			connection->m_analysis_flags = sinsp_connection::AF_REUSED;

			if (fdinfo->is_role_none() &&
			    !patch_network_role(thread_analyzer_info::get_thread_from_event(evt),
			                        fdinfo,
			                        incoming))
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
	// XXX: we expect it to return true and not fall into the `return connection` path, which would
	// mean
	// XXX: we ignore that preexisting connection and create a new one
	std::string scomm = evt->m_tinfo->get_comm();
	connection = m_ipv4_connections->add_connection(fdinfo->m_sockinfo.m_ipv4info,
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

void sinsp_analyzer_fd_listener::on_read(sinsp_evt* evt,
                                         int64_t tid,
                                         int64_t fd,
                                         sinsp_fdinfo_t* fdinfo,
                                         char* data,
                                         uint32_t original_len,
                                         uint32_t len)
{
	evt->set_iosize(original_len);

	if (fdinfo->is_file())
	{
		account_io(thread_analyzer_info::get_thread_from_event(evt),
		           fdinfo->m_name,
		           fdinfo->m_dev,
		           original_len,
		           evt->m_tinfo->m_latency,
		           analyzer_file_stat::io_direction::READ);
	}
	else if (fdinfo->is_ipv4_socket())
	{
		sinsp_connection* connection = nullptr;

		/////////////////////////////////////////////////////////////////////////////
		// Handle the connection
		/////////////////////////////////////////////////////////////////////////////
		if (should_report_network(fdinfo))
		{
			connection =
			    get_ipv4_connection(fdinfo, fdinfo->m_sockinfo.m_ipv4info, evt, tid, fd, true);
		}

		//
		// Attribute the read bytes to the proper connection side
		//
		if (connection == nullptr)
		{
			//
			// This happens when the connection table is full
			//
			return;
		}

		if (fdinfo->is_role_server())
		{
			connection->m_metrics.m_server.add_in(1, original_len);
		}
		else if (fdinfo->is_role_client())
		{
			thread_analyzer_info::get_thread_from_event(evt)->m_th_analysis_flags |=
			    thread_analyzer_info::flags::AF_IS_NET_CLIENT;
			connection->m_metrics.m_client.add_in(1, original_len);
		}
		else
		{
			ASSERT(false);
		}

		//
		// Determine the transaction direction.
		// recv(), recvfrom() and recvmsg() return 0 if the connection has been closed by the other
		// side.
		//
		sinsp_partial_transaction::direction trdir;

		uint16_t etype = evt->get_type();
		if (len == 0 && (etype == PPME_SOCKET_RECVFROM_X || etype == PPME_SOCKET_RECV_X ||
		                 etype == PPME_SOCKET_RECVMSG_X))
		{
			trdir = sinsp_partial_transaction::DIR_CLOSE;
		}
		else
		{
			trdir = sinsp_partial_transaction::DIR_IN;
		}

		protocol_manager::instance().protocol_event_received(evt,
		                                                     fd,
		                                                     fdinfo,
		                                                     data,
		                                                     original_len,
		                                                     len,
		                                                     connection,
		                                                     trdir,
		                                                     *m_analyzer);
	}
}

void sinsp_analyzer_fd_listener::on_write(sinsp_evt* evt,
                                          int64_t tid,
                                          int64_t fd,
                                          sinsp_fdinfo_t* fdinfo,
                                          char* data,
                                          uint32_t original_len,
                                          uint32_t len)
{
	evt->set_iosize(original_len);

	if (fdinfo->is_file())
	{
		account_io(thread_analyzer_info::get_thread_from_event(evt),
		           fdinfo->m_name,
		           fdinfo->m_dev,
		           original_len,
		           evt->m_tinfo->m_latency,
		           analyzer_file_stat::io_direction::WRITE);
	}
	else if (fdinfo->is_ipv4_socket())
	{
		sinsp_connection* connection = nullptr;

		/////////////////////////////////////////////////////////////////////////////
		// Handle the connection
		/////////////////////////////////////////////////////////////////////////////

		if (should_report_network(fdinfo))
		{
			connection =
			    get_ipv4_connection(fdinfo, fdinfo->m_sockinfo.m_ipv4info, evt, tid, fd, false);
		}

		//
		// Attribute the read bytes to the proper connection side
		//
		if (connection == nullptr)
		{
			//
			// This happens when the connection table is full
			//
			return;
		}

#ifndef _WIN32
		handle_statsd_write(evt, fdinfo, data, len);
#endif

		if (fdinfo->is_role_server())
		{
			connection->m_metrics.m_server.add_out(1, original_len);
		}
		else if (fdinfo->is_role_client())
		{
			thread_analyzer_info::get_thread_from_event(evt)->m_th_analysis_flags |=
			    thread_analyzer_info::flags::AF_IS_NET_CLIENT;
			connection->m_metrics.m_client.add_out(1, original_len);
		}
		else
		{
			ASSERT(false);
		}

		protocol_manager::instance().protocol_event_received(evt,
		                                                     fd,
		                                                     fdinfo,
		                                                     data,
		                                                     original_len,
		                                                     len,
		                                                     connection,
		                                                     sinsp_partial_transaction::DIR_OUT,
		                                                     *m_analyzer);
	}
}

#ifndef _WIN32

namespace
{
#define LOG_STATSD_MESSAGE(...)
}  // end namespace

void sinsp_analyzer_fd_listener::handle_statsd_write(sinsp_evt* const evt,
                                                     sinsp_fdinfo_t* const fdinfo,
                                                     const char* const data,
                                                     const uint32_t len) const
{
	if (m_analyzer->has_statsite_proxy() && fdinfo->is_role_client() && fdinfo->is_udp_socket() &&
	    fdinfo->get_serverport() == statsite_config::instance().get_udp_port())
	{
		const static bool use_forwarder =
		    configuration_manager::instance().get_config<bool>("statsd.use_forwarder")->get_value();

		auto tinfo = evt->get_thread_info(false);
		const std::string container_id = (tinfo != nullptr) ? tinfo->m_container_id : "";

		LOG_STATSD_MESSAGE(fdinfo, container_id);

		// If we're not using statsite_forwarder for container statsd
		// messages or if this is the host (i.e., not a container)
		if (!use_forwarder || container_id.empty())
		{
			// network endian representation of 127.0.0.1
			const uint32_t LOCALHOST_IPV4 = 0x0100007F;

			m_analyzer->inject_statsd_metric(
			    container_id,
			    (fdinfo->m_sockinfo.m_ipv4serverinfo.m_ip == LOCALHOST_IPV4),
			    data,
			    len);
		}
	}
}
#endif

void sinsp_analyzer_fd_listener::on_sendfile(sinsp_evt* evt, int64_t fdin, uint32_t len)
{
	int64_t tid = evt->get_tid();

	on_write(evt, tid, evt->m_tinfo->m_lastevent_fd, evt->m_fdinfo, NULL, len, 0);

	sinsp_fdinfo_t* fdinfoin = evt->m_tinfo->get_fd(fdin);
	if (fdinfoin == NULL)
	{
		return;
	}

	on_read(evt, tid, fdin, fdinfoin, NULL, len, 0);
}

void sinsp_analyzer_fd_listener::add_client_ipv4_connection(sinsp_evt* evt)
{
	int64_t tid = evt->get_tid();

	uint8_t flags = sinsp_connection::AF_NONE;
	if (evt->m_fdinfo->is_socket_failed())
	{
		flags = sinsp_connection::AF_FAILED;
	}
	else if (evt->m_fdinfo->is_socket_pending())
	{
		flags = sinsp_connection::AF_PENDING;
	}

	//
	// Add the tuple to the connection table
	//
	std::string scomm = evt->m_tinfo->get_comm();

	m_ipv4_connections->add_connection(evt->m_fdinfo->m_sockinfo.m_ipv4info,
	                                   &scomm,
	                                   evt->m_tinfo->m_pid,
	                                   tid,
	                                   evt->m_tinfo->m_lastevent_fd,
	                                   true,
	                                   evt->get_ts(),
	                                   flags,
	                                   evt->m_errorcode);

	thread_analyzer_info::get_thread_from_event(evt)->m_th_analysis_flags |=
	    thread_analyzer_info::flags::AF_IS_NET_CLIENT;
}

void sinsp_analyzer_fd_listener::on_connect(sinsp_evt* evt, uint8_t* packed_data)
{
	uint8_t family = *packed_data;

	//
	// Connection and transaction handling
	//
	// Since UDP sockets don't generate traffic
	// with connect, ignore them here. We'll
	// handle the connection at the first read/write
	if ((family == PPM_AF_INET || family == PPM_AF_INET6) && should_report_network(evt->m_fdinfo) &&
	    !evt->m_fdinfo->is_udp_socket())
	{
		//
		// Mark this fd as a transaction
		//
		if (evt->m_fdinfo->m_usrstate == NULL)
		{
			evt->m_fdinfo->m_usrstate = new sinsp_partial_transaction();
		}

		if (family == PPM_AF_INET)
		{
			add_client_ipv4_connection(evt);
		}
	}
	else if (family == PPM_AF_UNIX)
	{
		m_inspector->m_parser->set_unix_info(evt->m_fdinfo, packed_data);
	}

	//
	// Baseline update
	//
	ASSERT(m_falco_baseliner != NULL);
	m_falco_baseliner->on_connect(evt);
}

void sinsp_analyzer_fd_listener::on_accept(sinsp_evt* evt,
                                           int64_t newfd,
                                           uint8_t* packed_data,
                                           sinsp_fdinfo_t* new_fdinfo)
{
	std::string scomm = evt->m_tinfo->get_comm();
	int64_t tid = evt->get_tid();

	//
	// Connection and transaction handling
	//
	if (new_fdinfo->m_type == SCAP_FD_IPV4_SOCK && should_report_network(new_fdinfo))
	{
		//
		// Add the tuple to the connection table
		//
		m_ipv4_connections->add_connection(new_fdinfo->m_sockinfo.m_ipv4info,
		                                   &scomm,
		                                   evt->m_tinfo->m_pid,
		                                   tid,
		                                   newfd,
		                                   false,
		                                   evt->get_ts(),
		                                   sinsp_connection::AF_NONE,
		                                   0);
	}
	else if (new_fdinfo->m_type == SCAP_FD_UNIX_SOCK)
	{
		goto blupdate;
	}
	else if (new_fdinfo->m_type == SCAP_FD_UNINITIALIZED)
	{
		ASSERT(false);
		goto blupdate;
	}

	//
	// Mark this fd as a transaction
	//
	if (new_fdinfo->m_usrstate == NULL)
	{
		new_fdinfo->m_usrstate = new sinsp_partial_transaction();
	}

blupdate:
	//
	// Baseline update
	//
	ASSERT(m_falco_baseliner != NULL);
	m_falco_baseliner->on_accept(evt, new_fdinfo);
}

inline void sinsp_analyzer_fd_listener::flush_transaction(erase_fd_params* params)
{
	//
	// If this fd has an active transaction transaction table, mark it as unititialized
	//
	sinsp_connection* connection = nullptr;
	if (params->m_fdinfo->m_usrstate->is_active() && params->m_fdinfo->is_ipv4_socket())
	{
		connection =
		    m_analyzer->get_connection(params->m_fdinfo->m_sockinfo.m_ipv4info, params->m_ts);
	}

	if (connection)
	{
		params->m_fdinfo->m_usrstate->update(m_analyzer,
		                                     dynamic_cast<thread_analyzer_info*>(params->m_tinfo),
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
	if (params->m_fdinfo->is_cloned() &&
	    (params->m_fdinfo->is_ipv4_socket() || params->m_fdinfo->is_ipv6_socket()))
	{
		thread_analyzer_info* ptinfo =
		    dynamic_cast<thread_analyzer_info*>(params->m_tinfo)->get_parent_thread_info();
		if (ptinfo)
		{
			sinsp_fdinfo_t* pfdinfo = ptinfo->get_fd(params->m_fd);
			if (pfdinfo && pfdinfo->m_type == params->m_fdinfo->m_type &&
			    pfdinfo->m_name == params->m_fdinfo->m_name)
			{
				return;
			}
		}
	}

	//
	// If this fd has an active transaction transaction table, mark it as unititialized
	//
	if (params->m_fdinfo->is_transaction())
	{
		flush_transaction(params);
		params->m_fdinfo->m_usrstate->mark_inactive();
	}

	//
	// If the fd is in the connection table, schedule the connection for removal
	//
	if (params->m_fdinfo->is_ipv4_socket() && !params->m_fdinfo->has_no_role())
	{
		m_analyzer->remove_ipv4_connection(params->m_fdinfo->m_sockinfo.m_ipv4info);
	}
}

void sinsp_analyzer_fd_listener::on_socket_shutdown(sinsp_evt* evt)
{
	//
	// If this fd has an active transaction, update it and then mark it as unititialized
	//
	if (evt->m_fdinfo->is_transaction() && evt->m_fdinfo->m_usrstate->is_active())
	{
		sinsp_connection* connection = NULL;

		if (evt->m_fdinfo->is_ipv4_socket())
		{
			connection =
			    m_analyzer->get_connection(evt->m_fdinfo->m_sockinfo.m_ipv4info, evt->get_ts());
		}

		evt->m_fdinfo->m_usrstate->update(m_analyzer,
		                                  thread_analyzer_info::get_thread_from_event(evt),
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

void sinsp_analyzer_fd_listener::on_file_open(sinsp_evt* evt,
                                              const std::string& fullpath,
                                              uint32_t flags)
{
	if (evt->m_fdinfo && evt->m_errorcode == 0)
	{
		ASSERT(evt->m_fdinfo->is_file());
		ASSERT(evt->m_fdinfo->m_name == fullpath);
		bool is_write = flags & (PPM_O_WRONLY | PPM_O_CREAT | PPM_O_APPEND);
		if (evt->m_fdinfo->is_file())
		{
			if (is_write)
			{
				for (const auto& on_file_open_write_cb : m_on_file_open_write_cb)
				{
					on_file_open_write_cb(true,
					                      thread_analyzer_info::get_thread_from_event(evt),
					                      evt->get_ts(),
					                      fullpath,
					                      flags);
				}
			}

			for (const auto& on_file_open_cb : m_on_file_open_cb)
			{
				on_file_open_cb(is_write,
				                thread_analyzer_info::get_thread_from_event(evt),
				                evt->get_ts(),
				                fullpath,
				                flags);
			}
			//
			// File open count update
			//
			account_file_open(thread_analyzer_info::get_thread_from_event(evt),
			                  fullpath,
			                  evt->m_fdinfo->m_dev);
		}
	}
	else
	{
		// on errors we don't get the device info anyway so there's no point
		// in checking if evt->m_fdinfo != nullptr
		account_error(thread_analyzer_info::get_thread_from_event(evt), fullpath, 0);
	}

	//
	// Baseline update
	//
	ASSERT(m_falco_baseliner != NULL);
	m_falco_baseliner->on_file_open(evt, (std::string&)fullpath, flags);
}

void sinsp_analyzer_fd_listener::on_socket_status_changed(sinsp_evt* evt)
{
	ASSERT(evt->m_fdinfo);

	if (evt->m_fdinfo->is_ipv4_socket() && evt->m_errorcode != EAGAIN)
	{
		auto connection =
		    m_analyzer->get_connection(evt->m_fdinfo->m_sockinfo.m_ipv4info, evt->get_ts());
		if (connection)
		{
			connection->set_state(-evt->m_errorcode);
		}

        uint8_t flags = sinsp_connection::AF_NONE;
        if (evt->m_fdinfo->is_socket_failed())
        {
            flags = sinsp_connection::AF_FAILED;
        }
        else if (evt->m_fdinfo->is_socket_pending())
        {
            flags = sinsp_connection::AF_PENDING;
        }

        std::string scomm = evt->m_tinfo->get_comm();
        m_ipv4_connections->add_connection(evt->m_fdinfo->m_sockinfo.m_ipv4info,
                                           &scomm,
                                           evt->m_tinfo->m_pid,
                                           evt->get_tid(),
                                           evt->m_tinfo->m_lastevent_fd,
                                           true,
                                           evt->get_ts(),
                                           flags,
                                           evt->m_errorcode);
	}
}

void sinsp_analyzer_fd_listener::on_error(sinsp_evt* evt)
{
	ASSERT(evt->m_fdinfo);
	ASSERT(evt->m_errorcode != 0);

	if (evt->m_fdinfo)
	{
		if (evt->m_fdinfo->is_file())
		{
			account_error(thread_analyzer_info::get_thread_from_event(evt),
			              evt->m_fdinfo->m_name,
			              evt->m_fdinfo->m_dev);
		}
		else if (evt->m_fdinfo->is_transaction())
		{
			//
			// This attempts to flush a transaction when a read timeout happens.
			//
			erase_fd_params params;

			params.m_fdinfo = evt->m_fdinfo;
			params.m_tinfo = evt->m_tinfo;
			params.m_ts = evt->get_ts();
			params.m_fd = 0;
			enum ppm_event_category ecat = evt->m_info->category;

			//
			// We flush transaction if the I/O operation satisfies one of the
			// following conditions:
			//  - the FD is a server one, this a failed read AND it's the first read after a bunch
			//  of writes
			//  - the FD is a client one, this a failed write AND it's the first read after a bunch
			//  of reads
			// In other words, we try to capture the attempt at beginning a new transaction, even if
			// it fails because there's no data yet.
			//
			if ((params.m_fdinfo->is_role_server() &&
			     params.m_fdinfo->m_usrstate->m_direction == sinsp_partial_transaction::DIR_OUT &&
			     ecat == EC_IO_READ) ||
			    (params.m_fdinfo->is_role_client() &&
			     params.m_fdinfo->m_usrstate->m_direction == sinsp_partial_transaction::DIR_IN &&
			     ecat == EC_IO_WRITE))
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

void sinsp_analyzer_fd_listener::on_execve(sinsp_evt* evt)
{
	//
	// Baseline update
	//
	ASSERT(m_falco_baseliner != NULL);
	m_falco_baseliner->on_new_proc(evt, evt->get_thread_info());

	if (m_analyzer->is_tracking_environment())
	{
		thread_analyzer_info* tinfo = thread_analyzer_info::get_thread_from_event(evt);

		if (tinfo)
		{
			tinfo->main_thread_ainfo()->hash_environment(tinfo,
			                                             m_analyzer->get_environment_blacklist(),
			                                             true);
		}
	}
}

void sinsp_analyzer_fd_listener::on_bind(sinsp_evt* evt)
{
	//
	// Baseline update
	//
	ASSERT(m_falco_baseliner != NULL);
	m_falco_baseliner->on_bind(evt);
}

bool sinsp_analyzer_fd_listener::on_resolve_container(sinsp_container_manager* const manager,
                                                      sinsp_threadinfo* const tinfo,
                                                      const bool query_os_for_missing_info)
{
	bool resolved = false;

#if !defined(CYGWING_AGENT)
	resolved = m_analyzer->resolve_custom_container(manager,
	                                                dynamic_cast<thread_analyzer_info*>(tinfo),
	                                                query_os_for_missing_info);
#endif
	return resolved;
}

void sinsp_analyzer_fd_listener::on_clone(sinsp_evt* evt, sinsp_threadinfo* newtinfo)
{
	//
	// Baseline update
	//
	ASSERT(m_falco_baseliner != NULL);
	m_falco_baseliner->on_new_proc(evt, newtinfo);
}

inline bool sinsp_analyzer_fd_listener::should_account_io(const thread_analyzer_info* tinfo)
{
#if defined(HAS_CAPTURE)
	//
	// Exclude dragent files to be consistent with everything else
	//
	if (tinfo->m_pid == m_inspector->m_sysdig_pid)
	{
		return false;
	}
#endif
	return true;
}
void sinsp_analyzer_fd_listener::account_io(thread_analyzer_info* const tinfo,
                                            const std::string& name,
                                            const uint32_t dev,
                                            const uint32_t bytes,
                                            const uint64_t time_ns,
                                            const analyzer_file_stat::io_direction direction)
{
	if (!should_account_io(tinfo))
	{
		return;
	}

	m_files_stat[name].account_io(bytes, time_ns, direction);

	auto mt_ainfo = tinfo->main_thread_ainfo();
	if (m_analyzer->detailed_fileio_reporting())
	{
		mt_ainfo->m_files_stat[name].account_io(bytes, time_ns, direction);
	}

	if (dev != 0)
	{
		if (m_analyzer->fileio_device_reporting())
		{
			m_devs_stat[dev].account_io(bytes, time_ns, direction);
		}
		if (m_analyzer->detailed_fileio_device_reporting())
		{
			mt_ainfo->m_devs_stat[dev].account_io(bytes, time_ns, direction);
		}
	}
}

void sinsp_analyzer_fd_listener::account_file_open(thread_analyzer_info* tinfo,
                                                   const std::string& name,
                                                   uint32_t dev)
{
	if (!should_account_io(tinfo))
	{
		return;
	}

	m_files_stat[name].account_file_open();

	auto mt_ainfo = tinfo->main_thread_ainfo();
	if (m_analyzer->detailed_fileio_reporting())
	{
		mt_ainfo->m_files_stat[name].account_file_open();
	}

	if (dev != 0)
	{
		if (m_analyzer->fileio_device_reporting())
		{
			m_devs_stat[dev].account_file_open();
		}
		if (m_analyzer->detailed_fileio_device_reporting())
		{
			mt_ainfo->m_devs_stat[dev].account_file_open();
		}
	}
}

void sinsp_analyzer_fd_listener::account_error(thread_analyzer_info* tinfo,
                                               const std::string& name,
                                               uint32_t dev)
{
	if (!should_account_io(tinfo))
	{
		return;
	}

	m_files_stat[name].account_error();

	auto mt_ainfo = tinfo->main_thread_ainfo();
	if (m_analyzer->detailed_fileio_reporting())
	{
		mt_ainfo->m_files_stat[name].account_error();
	}

	if (dev != 0)
	{
		if (m_analyzer->fileio_device_reporting())
		{
			m_devs_stat[dev].account_error();
		}
		if (m_analyzer->detailed_fileio_device_reporting())
		{
			mt_ainfo->m_devs_stat[dev].account_error();
		}
	}
}

bool sinsp_analyzer_fd_listener::should_report_network(sinsp_fdinfo_t* fdinfo)
{
	return !c_blacklisted_ports.get_value().test(fdinfo->get_serverport());
}

void sinsp_analyzer_fd_listener::set_ipv4_connection_manager(
    sinsp_ipv4_connection_manager* const ipv4_connection_manager)
{
	m_ipv4_connections = ipv4_connection_manager;
}

port_list_config::port_list_config(const std::string& description, const std::string& key)
    : configuration_unit(
          key,
          "",
          "",
          description),  // yaml_configuration only supports key for get_merged_sequence
      m_data(),
      m_count(0)
{
}

std::string port_list_config::value_to_string() const
{
	std::stringstream out;
	out << "Count: " << m_count;

	return out.str();
}

std::string port_list_config::value_to_yaml() const
{
	// not currently supported
	return "";
}
bool port_list_config::string_to_value(const std::string& value)
{
	LOG_DEBUG("string_to_value() unsupported for port_list_config");
	return false;
}
void port_list_config::init(const yaml_configuration& raw_config)
{
	std::vector<uint16_t> raw_ports;

	raw_ports = raw_config.get_merged_sequence<uint16_t>(get_key());

	for (auto port : raw_ports)
	{
		m_data.set(port);
	}
	m_count = raw_ports.size();
}

const ports_set& port_list_config::get_value() const
{
	return m_data;
}
