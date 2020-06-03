#include "protocol_manager.h"

#include "analyzer_fd.h"  // for port_list_config
#include "analyzer_thread.h"
#include "sinsp.h"

port_list_config protocol_manager::c_known_ports("configured list of ports we assume are IP ports", "known_ports");

protocol_manager* protocol_manager::s_protocol_manager = new protocol_manager();

protocol_manager& protocol_manager::instance()
{
	return *protocol_manager::s_protocol_manager;
}

protocol_manager::protocol_manager()
    : feature_base(PROTOCOL_STATS,
                   &draiosproto::feature_status::set_protocol_stats_enabled,
                   {FULL_SYSCALLS})
{
}

void protocol_manager::protocol_event_received(sinsp_evt* evt,
                                               int64_t fd,
                                               sinsp_fdinfo_t* fdinfo,
                                               char* data,
                                               uint32_t original_len,
                                               uint32_t len,
                                               sinsp_connection* connection,
                                               sinsp_partial_transaction::direction trdir,
                                               sinsp_analyzer& analyzer)
{
	//
	// Check if this is a new transaction that needs to be initialized, and whose
	// protocol needs to be discovered.
	// NOTE: after two turns, we give up discovering the protocol and we consider this
	//       to be just IP.
	//
	sinsp_partial_transaction* trinfo = fdinfo->m_usrstate;

	if (trinfo == NULL)
	{
		fdinfo->m_usrstate = new sinsp_partial_transaction();
		trinfo = fdinfo->m_usrstate;
	}

	if (!trinfo->is_active() || (trinfo->m_n_direction_switches < 8 &&
	                             trinfo->m_type <= sinsp_partial_transaction::TYPE_IP))
	{
		//
		// New or just detected transaction. Detect the protocol and initialize the transaction.
		// Note: m_type can be bigger than TYPE_IP if the connection has been reset by something
		//       like a shutdown().
		//
		if (trinfo->m_type <= sinsp_partial_transaction::TYPE_IP)
		{
			sinsp_partial_transaction::type type =
			    detect_proto(evt, trinfo, trdir, (uint8_t*)data, len);

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
	if (trinfo->m_type != sinsp_partial_transaction::TYPE_UNKNOWN)
	{
		trinfo->update(&analyzer,
		               thread_analyzer_info::get_thread_from_event(evt),
		               fdinfo,
		               connection,
		               evt->get_lastevent_ts(),
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

sinsp_partial_transaction::type protocol_manager::detect_proto(
    sinsp_evt* evt,
    sinsp_partial_transaction* trinfo,
    sinsp_partial_transaction::direction trdir,
    uint8_t* buf,
    uint32_t buflen)
{
	if (!instance().get_enabled())
	{
		trinfo->m_protoparser = NULL;
		return sinsp_partial_transaction::TYPE_UNKNOWN;
	}

	uint16_t serverport = evt->m_fdinfo->get_serverport();

	if (buflen >= MIN_VALID_PROTO_BUF_SIZE)
	{
		if (protocol_http::instance().is_protocol(evt, trinfo, trdir, buf, buflen, serverport))
		{
			sinsp_http_parser* st = new sinsp_http_parser;
			trinfo->m_protoparser = (sinsp_protocol_parser*)st;
			return sinsp_partial_transaction::TYPE_HTTP;
		}
		if (protocol_mysql::instance().is_protocol(evt, trinfo, trdir, buf, buflen, serverport))
		{
			sinsp_mysql_parser* st = new sinsp_mysql_parser;
			trinfo->m_protoparser = (sinsp_protocol_parser*)st;
			return sinsp_partial_transaction::TYPE_MYSQL;
		}
		if (protocol_postgres::instance().is_protocol(evt, trinfo, trdir, buf, buflen, serverport))
		{
			sinsp_postgres_parser* st = new sinsp_postgres_parser;
			trinfo->m_protoparser = (sinsp_protocol_parser*)st;
			return sinsp_partial_transaction::TYPE_POSTGRES;
		}
		if (protocol_mongodb::instance().is_protocol(evt, trinfo, trdir, buf, buflen, serverport))
		{
			sinsp_mongodb_parser* st = new sinsp_mongodb_parser;
			trinfo->m_protoparser = (sinsp_protocol_parser*)st;
			return sinsp_partial_transaction::TYPE_MONGODB;
		}
		if ((buf[0] >= 0x14 && buf[0] <= 0x18) &&  // First byte matches TLS frame type
		         buf[1] == 3 &&                         // Matches TLS major version
		         (buf[2] >= 0 && buf[2] <= 3) &&        // Matches TLS minor version
		         // Besides detecting that it's TLS, we check if port belongs
		         // to well-known client/server protocol port
		         c_known_ports.get_value().test(serverport))
		{
			trinfo->m_protoparser = new sinsp_tls_parser();
			return sinsp_partial_transaction::TYPE_TLS;
		}
	}

	if (protocol_mysql::instance().get_enabled() && serverport == SRV_PORT_MYSQL)
	{
		//
		// This transaction has not been recognized yet, and the port is
		// the mysql one. Sometimes mysql splits the receive into multiple
		// reads, so we try to buffer this data and try again later
		//
		if ((evt->m_fdinfo->is_role_server() && trdir == sinsp_partial_transaction::DIR_IN) ||
		    (evt->m_fdinfo->is_role_client() && trdir == sinsp_partial_transaction::DIR_OUT))
		{
			if (trdir != trinfo->m_direction)
			{
				trinfo->m_reassembly_buffer.clear();
			}

			trinfo->m_reassembly_buffer.copy((char*)buf, buflen);
		}
	}

	// If we have not yet recognized a protocol, fallback to known client/server ports
	if (c_known_ports.get_value().test(serverport))
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
