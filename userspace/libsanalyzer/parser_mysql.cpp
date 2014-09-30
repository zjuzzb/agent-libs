#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_int.h"
#include "parser_mysql.h"

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
// Protocol specs can be found at 
// http://dev.mysql.com/doc/internals/en/client-server-protocol.html
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////


#ifdef HAS_ANALYZER

sinsp_mysql_parser::sinsp_mysql_parser()
{
	m_database = NULL;
}

inline void sinsp_mysql_parser::reset()
{
	m_parsed = false;
	m_is_valid = false;
	m_is_req_valid = false;
	m_reassembly_buf.clear();
	m_error_code = 0;
	m_msgtype = MT_NONE;
}

sinsp_protocol_parser::msg_type sinsp_mysql_parser::should_parse(sinsp_fdinfo_t* fdinfo, 
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
				return sinsp_protocol_parser::MSG_REQUEST;
			}
		}
	}

	return sinsp_protocol_parser::MSG_NONE;
}

bool sinsp_mysql_parser::parse_request(char* buf, uint32_t buflen)
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
		if(rbuf[MYSQL_OFFSET_SEQ_ID] == 1)
		{
			if(buflen + m_reassembly_buf.get_size() > MYSQL_OFFSET_DBANME)
			{
				//
				// Login packet
				//
				m_database = m_storage.strcopy(rbuf + MYSQL_OFFSET_DBANME, 
					rbufsize - MYSQL_OFFSET_DBANME);

				m_msgtype = MT_LOGIN;
				m_is_req_valid = true;
			}

			m_parsed = true;
		}
		else
		{
			if(rbuf[MYSQL_OFFSET_OPCODE] == MYSQL_OPCODE_QUERY)
			{
				m_statement = m_storage.strcopy(rbuf + MYSQL_OFFSET_STATEMENT, 
					rbufsize - MYSQL_OFFSET_STATEMENT);

//cerr << (m_statement + string("\n\n"));

				m_msgtype = MT_QUERY;
				m_is_req_valid = true;
			}

			m_parsed = true;
		}
	}
	else
	{
		//
		// If the buffer is smaller than 20 bytes, we assume that it's a fragment
		// and we store it for successive analysis
		//
		m_reassembly_buf.copy(buf, buflen);
	}

	return true;
}

bool sinsp_mysql_parser::parse_response(char* buf, uint32_t buflen)
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
		if(((uint8_t*)rbuf)[MYSQL_OFFSET_STATUS] == 0xff)
		{
			//
			// Error response
			//
			if(buflen + m_reassembly_buf.get_size() > MYSQL_OFFSET_ERROR_MESSAGE)
			{
				m_error_code = *(uint16_t*)(rbuf + MYSQL_OFFSET_ERROR_CODE);

				m_error_message = m_storage.strcopy(rbuf + MYSQL_OFFSET_ERROR_MESSAGE , 
					rbufsize - MYSQL_OFFSET_ERROR_MESSAGE);

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
		// If the buffer is smaller than 20 bytes, we assume that it's a fragment
		// and we store it for successive analysis
		//
		m_reassembly_buf.copy(buf, buflen);
	}

/*
if(m_error_code != 0)
{
	cerr << (string("status: ") + to_string(m_error_code) + " - " + m_error_message + string("\n\n\n"));
}
else
{
	cerr << (string("status: ") + to_string(m_error_code) + string("\n\n\n"));
}
*/

	return true;
}

#endif // HAS_ANALYZER
