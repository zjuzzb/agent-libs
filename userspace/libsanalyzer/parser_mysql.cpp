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

//
// Type of queries
//
const char* sql_toks[] = {"SELECT",
		"INSERT",
		"SET",
		"CREATE",
		"DELETE",
		"DROP",
		"REPLACE",
		"UPDATE",
		"USE",
		"SHOW",
		"LOCK",
		"UNLOCK",
		"ALTER"};

uint32_t sql_toklens[] = {sizeof("SELECT") - 1,
	sizeof("INSERT") - 1,
	sizeof("SET") - 1,
	sizeof("CREATE") - 1,
	sizeof("DELETE") - 1,
	sizeof("DROP") - 1,
	sizeof("REPLACE") - 1,
	sizeof("UPDATE") - 1,
	sizeof("USE") - 1,
	sizeof("SHOW") - 1,
	sizeof("LOCK") - 1,
	sizeof("UNLOCK") - 1,
	sizeof("ALTER") - 1};

//
// Tokens that denote the end of a select
//
const char* selectend_toks[] = {"WHERE",
		"AS"};

uint32_t selectend_toklens[] = {sizeof("WHERE") - 1,
	sizeof("AS") - 1};

///////////////////////////////////////////////////////////////////////////////
// sinsp_slq_query_parser implementation
///////////////////////////////////////////////////////////////////////////////
inline int32_t sinsp_slq_query_parser::find_tokens(const char* src, uint32_t srclen, uint32_t ntoks, char** toks, uint32_t* toklens, uint32_t* nskipped)
{
	uint32_t j;
	int32_t res = -1;
	const char* p = src;
	const char* pend = src + srclen;
	*nskipped = 0;

	//
	// Find the end of the word
	//
	while(*p != ' ' && *p != '\t' && *p != '\r' && *p != '\n' && *p != '(' && *p != ')')
	{
		if(p == pend)
		{
			return -1;
		}

		p++;
	}

	//
	// Do the comparison
	//
	if(m_braket_level == 0)
	{
		uint32_t toklen = (uint32_t)(p - src);

		for(j = 0; j < ntoks; j++)
		{
			if(toklen == toklens[j])
			{
				if(sinsp_strcmpi((char*)src, toks[j], toklen))
				{
					res = j;
				}
			}
		}
	}

	//
	// Skip next spaces
	//
	while(*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == '(' || *p == ')')
	{
		if(p == pend)
		{
			return -1;
		}

		if(*p == '(')
		{
			m_braket_level++;
		}

		if(*p == ')')
		{
			m_braket_level--;
			ASSERT(m_braket_level >= 0);
		}

		p++;
	}

	*nskipped = (uint32_t)(p - src);

	return res;
}

inline const char* sinsp_slq_query_parser::find_token(const char* str, uint32_t strlen,
													  const char* tofind, uint32_t tofind_len)
{
	const char* last = str + strlen - tofind_len - 1;
	
	if(last <= str)
	{
		ASSERT(false);
		return NULL;
	}

	for(; str <= last; str++)
	{
		if(*str == '(')
		{
			m_braket_level++;
		}

		if(*str == ')')
		{
			m_braket_level--;
			ASSERT(m_braket_level >= 0);
		}

		if(m_braket_level == 0)
		{
			if(sinsp_strcmpi((char*)str, (char*)tofind, tofind_len))
			{
				return str;
			}
		}
	}

	return NULL;
}

void sinsp_slq_query_parser::parse(char* query, uint32_t querylen)
{
	char* p = query;
	char* pend = query + querylen;
	m_table = NULL;

	//
	// Trim leading whitespaces
	//
	while(*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
	{
		if(p == pend)
		{
			m_statement_type = OT_NONE;
			return;
		}

		p++;
	}

	//
	// Find the first statement type token
	//
	uint32_t nskips = 1;
	m_statement_type = OT_NONE;
	m_braket_level = 0;
	char* src = query;
	uint32_t srclen = querylen;

	while(nskips != 0)
	{
		int32_t id = find_tokens(src, 
			srclen, 
			sizeof(sql_toks) / sizeof(sql_toks[0]), 
			(char**)sql_toks,
			sql_toklens,
			&nskips);

		src += nskips;
		srclen -= nskips;

		if(id != -1)
		{
			m_statement_type = (statement_type)(id + 1);
			break;
		}
	}

	if(m_statement_type == OT_SELECT || m_statement_type == OT_DELETE)
	{
		const char* sfrom = find_token(src, srclen, "from", sizeof("from") - 1);

		if(sfrom != NULL)
		{
			uint32_t fromlen = 0;

			ASSERT(sfrom < pend);

			sfrom = sfrom + sizeof("from") - 1;
			src = (char*)sfrom;
			srclen = pend - src;

			ASSERT(src < pend);

			uint32_t nskips = 1;
			ASSERT(m_braket_level == 0);

			while(nskips != 0)
			{
				int32_t id = find_tokens(src, 
					srclen, 
					sizeof(selectend_toks) / sizeof(selectend_toks[0]), 
					(char**)selectend_toks,
					selectend_toklens,
					&nskips);

				src += nskips;
				srclen -= nskips;

				if(id != -1)
				{
					m_table = m_str_storage->copy_and_trim((char*)sfrom, fromlen, 1);
					break;
				}

				fromlen += nskips;
			}
		}
	}	
}

const char* sinsp_slq_query_parser::get_statement_type_string()
{
	ASSERT(m_statement_type <= OT_ALTER);

	if(m_statement_type == 0)
	{
		return "<NA>";
	}
	else
	{
		return sql_toks[m_statement_type - 1];
	}
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_mysql_parser implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_mysql_parser::sinsp_mysql_parser() :
	m_query_parser(&m_storage)
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
				return sinsp_protocol_parser::MSG_RESPONSE;
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
			if(buflen + m_reassembly_buf.get_size() > MYSQL_OFFSET_UNAME)
			{
				//
				// Login packet
				//
				char* tbuf = rbuf + MYSQL_OFFSET_OPCODE;
				char* bufend = rbuf + rbufsize;

				uint32_t caps = *(uint32_t*)(tbuf);
				char* user = rbuf + MYSQL_OFFSET_UNAME;
				tbuf = user + strnlen((char *)user, rbufsize - MYSQL_OFFSET_UNAME) + 1;

				if(tbuf < bufend)
				{
					uint32_t pass_len = (caps & CAP_SECURE_CONNECTION ? *tbuf++ : strlen((char *)tbuf));
					tbuf += pass_len;

					if(tbuf < bufend)
					{
						char* db = (caps & CAP_CONNECT_WITH_DB ? tbuf : (char*)"<NA>");

						m_database = m_storage.strcopy(db, bufend - tbuf);

						m_msgtype = MT_LOGIN;
						m_is_req_valid = true;
//cerr << (string("login: ") + user + " - " + m_database + string("\n\n\n"));
					}
				}
			}

			m_parsed = true;
		}
		else
		{
			if(rbuf[MYSQL_OFFSET_OPCODE] == MYSQL_OPCODE_QUERY)
			{
				//
				// Query packet
				//
				uint32_t querylen = rbufsize - MYSQL_OFFSET_STATEMENT;

				m_statement = m_storage.strcopy(rbuf + MYSQL_OFFSET_STATEMENT, 
					querylen);

				m_query_parser.parse(m_statement, querylen);

				m_msgtype = MT_QUERY;
				m_is_req_valid = true;
			}

			m_parsed = true;
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
		// If the buffer is smaller than 4 bytes, we assume that it's a fragment
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
