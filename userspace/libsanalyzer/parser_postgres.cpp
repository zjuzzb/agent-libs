#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_int.h"
#include "parser_postgres.h"
#include "sqlparser.h"

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
// Protocol specs can be found at 
// http://dev.postgres.com/doc/internals/en/client-server-protocol.html
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////


#ifdef HAS_ANALYZER

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

sinsp_protocol_parser::msg_type sinsp_postgres_parser::should_parse(sinsp_fdinfo_t* fdinfo, 
																 sinsp_partial_transaction::direction dir,
																 bool is_switched,
																 char* buf, uint32_t buflen)
{
	if((fdinfo->is_role_server() && dir == sinsp_partial_transaction::DIR_IN) ||
		(fdinfo->is_role_client() && dir == sinsp_partial_transaction::DIR_OUT))
	{
		if(is_switched)
		{
			reset();
			return sinsp_protocol_parser::MSG_REQUEST;
		}
		else
		{
			if(!m_parsed)
			{
				return sinsp_protocol_parser::MSG_REQUEST;
			}
		}
	}
	else if((fdinfo->is_role_server() && dir == sinsp_partial_transaction::DIR_OUT) ||
		(fdinfo->is_role_client() && dir == sinsp_partial_transaction::DIR_IN))
	{
		if(is_switched)
		{
			m_parsed = false;
			m_reassembly_buf.clear();
			return sinsp_protocol_parser::MSG_RESPONSE;
		}
		else
		{
			if(!m_parsed)
			{
				return sinsp_protocol_parser::MSG_RESPONSE;
			}
		}
	}

	return sinsp_protocol_parser::MSG_NONE;
}

bool sinsp_postgres_parser::parse_request(char* buf, uint32_t buflen)
{
	if(buflen + m_reassembly_buf.get_size() > 4)
	{
		char* rbuf;
		uint32_t rbufsize;

		//
		// Reconstruct the buffer
		//
		if(m_reassembly_buf.get_size() == 0)
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
		switch(rbuf[0])
		{
		case 'Q':
		{
			//
			// Query packet
			// |Q|size(uint32)|query string ending with \0|
			//
			uint32_t querylen;
			memcpy(&querylen, rbuf+1, sizeof(uint32_t));
			// From packet size extract string size
			querylen -= sizeof(uint32_t);
			uint32_t copied_size;

			m_statement = m_storage.strcopy(rbuf + 1 + sizeof(uint32_t), 
				querylen, &copied_size);

			m_query_parser.parse(m_statement, copied_size);

			m_msgtype = MT_QUERY;
			m_is_req_valid = true;			
			break;
		}
		}
		/*
		TODO: Login stuff, use later
		if(rbuf[0] == 1)
		{
			if(buflen + m_reassembly_buf.get_size() > POSTGRES_OFFSET_UNAME)
			{
				//
				// Login packet
				//
				char* tbuf = rbuf + POSTGRES_OFFSET_OPCODE;
				char* bufend = rbuf + rbufsize;

				uint32_t caps = *(uint32_t*)(tbuf);
				char* user = rbuf + POSTGRES_OFFSET_UNAME;
				tbuf = user + strnlen((char *)user, rbufsize - POSTGRES_OFFSET_UNAME) + 1;

				if(tbuf < bufend)
				{
					uint32_t pass_len = (caps & CAP_SECURE_CONNECTION ? *tbuf++ : strlen((char *)tbuf));
					tbuf += pass_len;

					if(tbuf < bufend)
					{
						//char* db = (caps & CAP_CONNECT_WITH_DB ? tbuf : (char*)"<NA>");
						//m_database = m_storage.strcopy(db, bufend - tbuf);

						m_msgtype = MT_LOGIN;
						m_is_req_valid = true;
					}
				}
			}
		}*/
		m_parsed = true;
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

bool sinsp_postgres_parser::parse_response(char* buf, uint32_t buflen)
{
	if(buflen + m_reassembly_buf.get_size() > 4)
	{
		char* rbuf;
		uint32_t rbufsize;

		//
		// Reconstruct the buffer
		//
		if(m_reassembly_buf.get_size() == 0)
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
		if(((uint8_t*)rbuf)[POSTGRES_OFFSET_STATUS] == 0xff)
		{
			//
			// Error response
			//
			if(buflen + m_reassembly_buf.get_size() > POSTGRES_OFFSET_ERROR_MESSAGE)
			{
				uint32_t copied_size;
				m_error_code = *(uint16_t*)(rbuf + POSTGRES_OFFSET_ERROR_CODE);

				m_error_message = m_storage.strcopy(rbuf + POSTGRES_OFFSET_ERROR_MESSAGE , 
					rbufsize - POSTGRES_OFFSET_ERROR_MESSAGE, &copied_size);

				m_is_valid = true;
			}

			m_parsed = true;
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

#endif // HAS_ANALYZER
