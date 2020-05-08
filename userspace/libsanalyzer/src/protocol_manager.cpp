#include "analyzer_thread.h"
#include "protocol_manager.h"
#include "analyzer_fd.h" // for port_list_config
#include "sinsp.h"

namespace
{
const char* const sql_querystart_toks[] = {"select",
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
                                           "alter"};

uint32_t s_http_options_intval = (*(uint32_t*)HTTP_OPTIONS_STR);
uint32_t s_http_get_intval = (*(uint32_t*)HTTP_GET_STR);
uint32_t s_http_head_intval = (*(uint32_t*)HTTP_HEAD_STR);
uint32_t s_http_post_intval = (*(uint32_t*)HTTP_POST_STR);
uint32_t s_http_put_intval = (*(uint32_t*)HTTP_PUT_STR);
uint32_t s_http_delete_intval = (*(uint32_t*)HTTP_DELETE_STR);
uint32_t s_http_trace_intval = (*(uint32_t*)HTTP_TRACE_STR);
uint32_t s_http_connect_intval = (*(uint32_t*)HTTP_CONNECT_STR);
uint32_t s_http_resp_intval = (*(uint32_t*)HTTP_RESP_STR);

port_list_config c_known_ports("configured list of ports we assume are IP ports", "known_ports");

}  // namespace

protocol_manager* protocol_manager::s_protocol_manager = new protocol_manager();

protocol_manager& protocol_manager::instance()
{
	return *protocol_manager::s_protocol_manager;
}

protocol_manager::protocol_manager() {}

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
	uint16_t serverport = evt->m_fdinfo->get_serverport();

	if (buflen >= MIN_VALID_PROTO_BUF_SIZE)
	{
		//
		// Detect HTTP
		//
		if (*(uint32_t*)buf == s_http_get_intval || *(uint32_t*)buf == s_http_post_intval ||
		    *(uint32_t*)buf == s_http_put_intval || *(uint32_t*)buf == s_http_delete_intval ||
		    *(uint32_t*)buf == s_http_trace_intval || *(uint32_t*)buf == s_http_connect_intval ||
		    *(uint32_t*)buf == s_http_options_intval ||
		    (*(uint32_t*)buf == s_http_resp_intval && buf[4] == '/'))
		{
			sinsp_http_parser* st = new sinsp_http_parser;
			trinfo->m_protoparser = (sinsp_protocol_parser*)st;

			return sinsp_partial_transaction::TYPE_HTTP;
		}
		//
		// Detect mysql
		//
		else if (serverport == SRV_PORT_MYSQL)
		{
			uint8_t* tbuf;
			uint32_t tbuflen;
			uint32_t stsize = trinfo->m_reassembly_buffer.get_size();

			if (stsize != 0)
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

			if (tbuflen > 5)  // min length
			{
				//
				// This detects a server greetings message, which is the first message sent by the
				// server
				//
				if (*(uint16_t*)tbuf == tbuflen - 4  // first 3 bytes are length
				    && tbuf[2] == 0x00               // 3rd byte of packet length
				    && tbuf[3] == 0)  // Sequence number is zero for the beginning of a query
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
					if (tbuf[0] == 3)
					{
						uint32_t downcase_buf;
						memcpy(&downcase_buf, tbuf + 1, sizeof(uint32_t));
						downcase_buf |= 0x20202020;  // downcase all chars
						for (uint32_t j = 0;
						     j < sizeof(sql_querystart_toks) / sizeof(sql_querystart_toks[0]);
						     j++)
						{
							if (downcase_buf == *(uint32_t*)sql_querystart_toks[j])
							{
								sinsp_mysql_parser* st = new sinsp_mysql_parser;
								trinfo->m_protoparser = (sinsp_protocol_parser*)st;
								return sinsp_partial_transaction::TYPE_MYSQL;
							}
						}
					}
					else if (tbuflen > 8)
					{
						//
						// This detects a query that is received as a NON fragmented buffer.
						//
						if (tbuf[4] == 3)
						{
							uint32_t downcase_buf;
							memcpy(&downcase_buf, tbuf + 5, sizeof(uint32_t));
							downcase_buf |= 0x20202020;  // downcase all chars
							for (uint32_t j = 0;
							     j < sizeof(sql_querystart_toks) / sizeof(sql_querystart_toks[0]);
							     j++)
							{
								if (downcase_buf == *(uint32_t*)sql_querystart_toks[j])
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
		else if (serverport == SRV_PORT_POSTGRES)
		{
			uint8_t* tbuf;
			uint32_t tbuflen;
			uint32_t stsize = trinfo->m_reassembly_buffer.get_size();

			if (stsize != 0)
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
			tbuf = buf;
			tbuflen = buflen;

			if (tbuflen > 5)  // min length
			{
				if (tbuf[0] == 'Q')  // Prepare statement commmand
				{
					uint32_t downcase_buf;
					memcpy(&downcase_buf, tbuf + 5, sizeof(uint32_t));
					downcase_buf |= 0x20202020;  // downcase all chars
					for (uint32_t j = 0;
					     j < sizeof(sql_querystart_toks) / sizeof(sql_querystart_toks[0]);
					     j++)
					{
						if (downcase_buf == *(uint32_t*)sql_querystart_toks[j])
						{
							sinsp_postgres_parser* st = new sinsp_postgres_parser;
							trinfo->m_protoparser = (sinsp_protocol_parser*)st;
							return sinsp_partial_transaction::TYPE_POSTGRES;
						}
					}
				}
				else if (tbuf[0] == 'P')  // Prepare statement commmand
				{
					uint32_t downcase_buf;
					memcpy(&downcase_buf, tbuf + 6, sizeof(uint32_t));
					downcase_buf |= 0x20202020;  // downcase all chars
					for (uint32_t j = 0;
					     j < sizeof(sql_querystart_toks) / sizeof(sql_querystart_toks[0]);
					     j++)
					{
						if (downcase_buf == *(uint32_t*)sql_querystart_toks[j])
						{
							sinsp_postgres_parser* st = new sinsp_postgres_parser;
							trinfo->m_protoparser = (sinsp_protocol_parser*)st;
							return sinsp_partial_transaction::TYPE_POSTGRES;
						}
					}
				}
				else if (*(uint32_t*)(tbuf + sizeof(uint32_t)) == 0x00000300)  // startup command
				{
					sinsp_postgres_parser* st = new sinsp_postgres_parser;
					trinfo->m_protoparser = (sinsp_protocol_parser*)st;
					return sinsp_partial_transaction::TYPE_POSTGRES;
				}
				else if (tbuf[0] == 'E' &&
				         htonl(*(uint32_t*)(tbuf + 1)) < 2000)  // error or execute command
				{
					sinsp_postgres_parser* st = new sinsp_postgres_parser;
					trinfo->m_protoparser = (sinsp_protocol_parser*)st;
					return sinsp_partial_transaction::TYPE_POSTGRES;
				}
			}
		}
		else if (buflen >= 16 && (*(int32_t*)(buf + 12) == 1 ||
		                          (*(int32_t*)(buf + 12) > 2000 && *(int32_t*)(buf + 12) < 2008)))
		{
			sinsp_mongodb_parser* st = new sinsp_mongodb_parser;
			trinfo->m_protoparser = (sinsp_protocol_parser*)st;
			return sinsp_partial_transaction::TYPE_MONGODB;
		}
		else if ((buf[0] >= 0x14 && buf[0] <= 0x18) &&  // First byte matches TLS frame type
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

	if (serverport == SRV_PORT_MYSQL)
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
