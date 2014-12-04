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
		if ( rbuf[0] == 'Q' ||
			 ( rbuf[0] == 'P' && rbuf[5] == 0 ))
		{
			//
			// Query packet
			// |Q|size(uint32)|query string ending with \0|
			//
			// Parse packet
			// |P|size(uint32)|name|query string| ....
			//
			uint32_t querylen;
			char* querypos;
			memcpy(&querylen, rbuf+1, sizeof(uint32_t));
			querylen=ntohl(querylen);
			printf("postgres pktlen: %d\n", querylen);

			uint32_t copied_size;
			if ( rbuf[0] == 'Q')
			{
				querypos = rbuf + 1 + sizeof(uint32_t);
			}
			else
			{
				querypos = rbuf + 1 + sizeof(uint32_t) + 1;
			}
			m_statement = m_storage.strcopy(querypos,
				querylen, &copied_size);
			printf("postgres statement: %s\n", m_statement);
			m_query_parser.parse(m_statement, copied_size);

			m_msgtype = MT_QUERY;
			m_is_req_valid = true;			
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
		if( rbuf[0] == 'E')
		{
			//
			// Error response
			//
			for(int j = 6; j < rbufsize-1; ++j)
			{
				if(rbuf[j] == 0)
				{
					if(rbuf[j+1] == 'C')
					{
						m_error_code = atoi(rbuf + j + 2);
						m_is_valid = true;
					}
					else if (rbuf[j+1] == 'M')
					{
						uint32_t copied_size;
						m_error_message = m_storage.strcopy(rbuf + j + 2 ,
							rbufsize - j, &copied_size);
						m_is_valid = true;
						break;
					}
				}
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
