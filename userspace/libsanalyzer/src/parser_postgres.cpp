#include "analyzer_int.h"
#include "parser_postgres.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "sqlparser.h"

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
// Protocol specs can be found at
// http://www.postgresql.org/docs/9.2/static/protocol-message-formats.html
// http://www.postgresql.org/docs/9.2/static/protocol-error-fields.html
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

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
}

protocol_postgres* protocol_postgres::s_protocol_postgres = new protocol_postgres();

protocol_postgres& protocol_postgres::instance()
{
	return *protocol_postgres::s_protocol_postgres;
}

protocol_postgres::protocol_postgres()
    : protocol_base(),
      feature_base(POSTGRES_STATS,
                   &draiosproto::feature_status::set_postgres_stats_enabled,
                   {PROTOCOL_STATS})
{
}

bool protocol_postgres::is_protocol(sinsp_evt* evt,
                                    sinsp_partial_transaction* trinfo,
                                    sinsp_partial_transaction::direction trdir,
                                    const uint8_t* buf,
                                    uint32_t buflen,
                                    uint16_t serverport) const
{
	if (!get_enabled())
	{
		return false;
	}

	if (serverport == SRV_PORT_POSTGRES)
	{
		const uint8_t* tbuf;
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

		// do we really want to unconditionally ignore the reassembly buffer?
		// if we do, why even populate it at all?
		// SMAGENT-2516
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
						return true;
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
						return true;
					}
				}
			}
			else if (*(uint32_t*)(tbuf + sizeof(uint32_t)) == 0x00000300)  // startup command
			{
				return true;
			}
			else if (tbuf[0] == 'E' &&
			         htonl(*(uint32_t*)(tbuf + 1)) < 2000)  // error or execute command
			{
				return true;
			}
		}
	}
	return false;
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_postgres_parser implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_postgres_parser::sinsp_postgres_parser()
{
	m_database = NULL;
}

inline void sinsp_postgres_parser::reset()
{
	m_parsed = false;
	m_is_valid = false;
	m_is_req_valid = false;
	m_reassembly_buf.clear();
	m_storage.clear();
	m_error_code = 0;
	m_msgtype = MT_NONE;
}

sinsp_postgres_parser::proto sinsp_postgres_parser::get_type()
{
	return sinsp_protocol_parser::PROTO_POSTGRES;
}

sinsp_protocol_parser::msg_type sinsp_postgres_parser::should_parse(
    sinsp_fdinfo_t* fdinfo,
    sinsp_partial_transaction::direction dir,
    bool is_switched,
    const char* buf,
    uint32_t buflen)
{
	if ((fdinfo->is_role_server() && dir == sinsp_partial_transaction::DIR_IN) ||
	    (fdinfo->is_role_client() && dir == sinsp_partial_transaction::DIR_OUT))
	{
		if (is_switched)
		{
			reset();
			return sinsp_protocol_parser::MSG_REQUEST;
		}
		else
		{
			if (!m_parsed)
			{
				return sinsp_protocol_parser::MSG_REQUEST;
			}
		}
	}
	else if ((fdinfo->is_role_server() && dir == sinsp_partial_transaction::DIR_OUT) ||
	         (fdinfo->is_role_client() && dir == sinsp_partial_transaction::DIR_IN))
	{
		if (is_switched)
		{
			m_parsed = false;
			m_reassembly_buf.clear();
			return sinsp_protocol_parser::MSG_RESPONSE;
		}
		else
		{
			if (!m_parsed)
			{
				return sinsp_protocol_parser::MSG_RESPONSE;
			}
		}
	}

	return sinsp_protocol_parser::MSG_NONE;
}

bool sinsp_postgres_parser::parse_request(const char* buf, uint32_t buflen)
{
	if (buflen + m_reassembly_buf.get_size() > 4)
	{
		const char* rbuf;
		uint32_t rbufsize;

		//
		// Reconstruct the buffer
		//
		if (m_reassembly_buf.get_size() == 0)
		{
			rbuf = buf;
			rbufsize = buflen;
		}
		else
		{
			m_reassembly_buf.copy(buf, buflen);
			rbuf = m_reassembly_buf.get_buf();
			rbufsize = m_reassembly_buf.get_size();
		}

		//
		// Do the parsing
		//
		if (rbuf[0] == 'Q' || (rbuf[0] == 'P' && rbuf[5] == 0))
		{
			//
			// Query packet
			// |Q|size(uint32)|query string ending with \0|
			//
			// Parse packet
			// |P|size(uint32)|name|query string| ....
			//
			uint32_t querylen;
			const char* querypos;
			memcpy(&querylen, rbuf + 1, sizeof(uint32_t));
			querylen = MIN(ntohl(querylen), rbufsize) - sizeof(uint32_t);

			uint32_t copied_size;
			if (rbuf[0] == 'Q')
			{
				querypos = rbuf + 1 + sizeof(uint32_t);
			}
			else
			{
				// There is an extra \0 byte on P queries, to denote
				// an empty "name" of the query
				querypos = rbuf + 1 + sizeof(uint32_t) + 1;
				querylen -= 1;
			}
			m_statement = m_storage.strcopy(querypos, querylen, &copied_size);
			m_query_parser.parse(m_statement, copied_size);

			m_msgtype = MT_QUERY;
			m_parsed = true;
			m_is_req_valid = true;
		}
	}
	else
	{
		//
		// If the buffer is smaller than 4 bytes, we assume that it's a fragment
		// and we store it for successive analysis
		//
		m_reassembly_buf.copy(buf, buflen);
	}

	return true;
}

bool sinsp_postgres_parser::parse_response(const char* buf, uint32_t buflen)
{
	if (buflen + m_reassembly_buf.get_size() > 4)
	{
		const char* rbuf;

		//
		// Reconstruct the buffer
		//
		if (m_reassembly_buf.get_size() == 0)
		{
			rbuf = buf;
			//			rbufsize = buflen;
		}
		else
		{
			m_reassembly_buf.copy(buf, buflen);
			rbuf = m_reassembly_buf.get_buf();
		}

		//
		// Do the parsing
		//
		if (rbuf[0] == 'E' && htonl(*(uint32_t*)(rbuf + 1)) < 2000)
		{
			//
			// Error response
			//
			m_error_code = 1;  // Just to say that there is an error
			m_parsed = true;
			m_is_valid = true;
		}
		else
		{
			//
			// OK response
			//
			m_parsed = true;
			m_is_valid = true;
		}
	}
	else
	{
		//
		// If the buffer is smaller than 4 bytes, we assume that it's a fragment
		// and we store it for successive analysis
		//
		m_reassembly_buf.copy(buf, buflen);
	}

	return true;
}
