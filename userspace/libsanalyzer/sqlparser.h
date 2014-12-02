#ifdef HAS_ANALYZER
#pragma once

class sinsp_slq_query_parser
{
public:	
	enum statement_type
	{
		OT_NONE = 0,
		OT_SELECT = 1, //
		OT_INSERT = 2, //
		OT_SET = 3, //
		OT_CREATE = 4, //
		OT_DELETE = 5, //
		OT_DROP = 6, //
		OT_REPLACE = 7, // 
		OT_UPDATE = 8, //
		OT_USE = 9,
		OT_SHOW = 10,
		OT_LOCK = 11,
		OT_UNLOCK = 12,
		OT_ALTER = 13,
	};
	
	sinsp_slq_query_parser()
	{
		m_table = NULL;
	}

	void parse(char* query, uint32_t querylen);

	const char* get_statement_type_string();

	statement_type m_statement_type;
	char* m_table;

private:
	inline int32_t find_tokens(const char* src, uint32_t srclen, uint32_t ntoks, char** toks, uint32_t* toklens, uint32_t* nskipped);
	inline const char* find_token(const char* str, uint32_t strlen, const char* tofind, uint32_t tofind_len);
	void extract_table(char*src, uint32_t srclen, char* start_token, uint32_t start_token_len, const char** end_tokens, uint32_t* end_toklens, uint32_t n_end_tokens);
	
	int32_t m_braket_level;
	sinsp_autobuffer m_str_storage;
};

#endif // HAS_ANALYZER
