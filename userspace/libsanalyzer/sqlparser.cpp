#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_int.h"
#include "sqlparser.h"

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
		"ALTER",
		//"VACUUM",
		//"TRUNCATE"
};

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
	sizeof("ALTER") - 1,
	sizeof("VACUUM") - 1,
	sizeof("TRUNCATE") -1
};

//
// Tokens that denote the end of a select
//
const char* selectend_toks[] = {"WHERE",
		"AS",
		"LIMIT"};

uint32_t selectend_toklens[] = {sizeof("WHERE") - 1,
	sizeof("AS") - 1,
	sizeof("LIMIT") - 1
};

//
// Tokens that denote the end of an insert
//
const char* insertend_toks[] = {"VALUES"};
uint32_t insertend_toklens[] = {sizeof("VALUES") - 1};

//
// Tokens that denote the end of an update
//
const char* updateend_toks[] = {"SET"};
uint32_t updateend_toklens[] = {sizeof("SET") - 1};

const char* truncateend_toks[] = { "RESTART", "CONTINUE","CASCADE", "RESTRICT" };
uint32_t truncateend_toklens[] = {sizeof("RESTART")-1,
								  sizeof("CONTINUE")-1,
								  sizeof("CASCADE")-1,
								  sizeof("RESTRICT")-1
								 };
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
			*nskipped = (uint32_t)(p - src);
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
			*nskipped = (uint32_t)(p - src);
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

// Look up a token on a string, skips characters inside ()
inline const char* sinsp_slq_query_parser::find_token(const char* str, uint32_t strlen,
													  const char* tofind, uint32_t tofind_len)
{
	const char* last = str + strlen - tofind_len - 1;
	
	if(last <= str)
	{
		// Seems that is possible this situation, ex "INSERT" as src and "INTO" as tofind
		//ASSERT(false);
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

char* sinsp_slq_query_parser::copy_and_cleanup_table_name(const char *data, uint64_t size)
{
	//
	// Skip initial stuff
	//
	uint16_t inside_bracket = 0;
	while(*data == ' ' || *data == '\t' || *data == '\r' || *data == '\n' ||
		  *data == ';' || *data == '(' || *data == ')' || inside_bracket)
	{
		data++;
		size--;

		if(size == 0)
		{
			return NULL;
		}
		if ( *data == '(')
		{
			++inside_bracket;
		}
		if ( *data == ')')
		{
			--inside_bracket;
		}
	}

	//
	// Skip initial spaces
	//
	const char* end = data + size - 1;

	while(*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n' ||
		  *end == ';' || *end == '(' || *end == ')' || inside_bracket )
	{
		end--;
		size--;

		if(size == 0)
		{
			return NULL;
		}
		if ( *end == ')')
		{
			++inside_bracket;
		}
		if ( *end == '(')
		{
			--inside_bracket;
		}
	}

	//
	// Copy the string
	//
	return m_str_storage.copy(data, size, 1);
}

void sinsp_slq_query_parser::extract_table(char*src, uint32_t srclen, char* start_token, uint32_t start_token_len,
	const char** end_tokens, uint32_t* end_toklens, uint32_t n_end_tokens, bool cleanup_name)
{
	char* pend = src + srclen;
	const char* sfrom;

	if(start_token != NULL)
	{
		sfrom = find_token(src, srclen, start_token, start_token_len);
	}
	else
	{
		sfrom = src;
	}

	if(sfrom != NULL)
	{
		uint32_t fromlen = 0;

		ASSERT(sfrom < pend);

		sfrom = sfrom + start_token_len;
		src = (char*)sfrom;
		srclen = pend - src;

		ASSERT(src < pend);

		uint32_t nskips = 1;
		ASSERT(m_braket_level == 0);

		while(nskips != 0)
		{
			int32_t id = find_tokens(src, 
				srclen, 
				n_end_tokens, 
				(char**)end_tokens,
				end_toklens,
				&nskips);

			src += nskips;
			srclen -= nskips;

			if(id != -1)
			{
				if (cleanup_name)
				{
					m_table = copy_and_cleanup_table_name(sfrom, fromlen);
				}
				else
				{
					m_table = m_str_storage.copy_and_trim((char*)sfrom, fromlen, 1);
				}
				break;
			}
			else if(srclen == 0)
			{
				fromlen += nskips;
				if (cleanup_name)
				{
					m_table = copy_and_cleanup_table_name(sfrom, fromlen);
				}
				else
				{
					m_table = m_str_storage.copy_and_trim((char*)sfrom, fromlen, 1);
				}
				break;
			}

			fromlen += nskips;
		}
	}
}

void sinsp_slq_query_parser::parse(char* query, uint32_t querylen)
{
	char* p = query;
	char* pend = query + querylen;
	m_table = NULL;
	m_str_storage.clear();

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

	// trim final space
	while ( srclen > 0 && ( src[srclen-1] == ';' ||
			src[srclen-1] == '\r' || src[srclen-1] == '\n' ||
			src[srclen-1] == ' ' || src[srclen-1] == '\t')
		)
	{
		--srclen;
	}

	switch(m_statement_type)
	{
	case OT_SELECT:
	case OT_DELETE:
		extract_table(src, srclen, (char*)"from", sizeof("from") - 1,
			selectend_toks, selectend_toklens, 
			sizeof(selectend_toks) / sizeof(selectend_toks[0]));
		break;
	case OT_INSERT:
	case OT_REPLACE:
		extract_table(src, srclen, (char*)"into", sizeof("into") - 1,
			insertend_toks, insertend_toklens, 
			sizeof(insertend_toks) / sizeof(insertend_toks[0]), true);
		break;
	case OT_UPDATE:
		extract_table(src, srclen, NULL, 0,
			updateend_toks, updateend_toklens, 
			sizeof(updateend_toks) / sizeof(updateend_toks[0]));
		break;
	/*case OT_VACUUM:
		extract_table(src, srclen, NULL, 0,
			NULL, NULL, 0);
		break;
	case OT_TRUNCATE:
		extract_table(src, srclen, NULL, 0,
			truncateend_toks, truncateend_toklens,
			sizeof(truncateend_toks) / sizeof(truncateend_toks[0]));
		break;*/
	default:
		break;
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

#endif
