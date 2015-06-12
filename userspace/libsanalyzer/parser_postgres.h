///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
// Protocol specs can be found at 
// http://dev.postgres.com/doc/internals/en/client-server-protocol.html
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

#ifdef HAS_ANALYZER

#pragma once
#include "sqlparser.h"

///////////////////////////////////////////////////////////////////////////////
// POSTGRES parser
///////////////////////////////////////////////////////////////////////////////

class sinsp_postgres_parser : public sinsp_protocol_parser
{
public:
	enum msg_type
	{
		MT_NONE = 0,
		MT_LOGIN,
		MT_QUERY,
	};

	sinsp_postgres_parser();
	sinsp_protocol_parser::msg_type should_parse(sinsp_fdinfo_t* fdinfo, 
		sinsp_partial_transaction::direction dir,
		bool is_switched,
		char* buf, uint32_t buflen);
	bool parse_request(char* buf, uint32_t buflen);
	bool parse_response(char* buf, uint32_t buflen);
	proto get_type();

	char* m_query;

private:
	inline void reset();

	sinsp_autobuffer m_reassembly_buf;
	bool m_parsed;
	sinsp_autobuffer m_storage;

	msg_type m_msgtype;
	char* m_database;
	char* m_statement;
	char* m_error_message;
	uint16_t m_error_code;

	sinsp_slq_query_parser m_query_parser;

	friend class sinsp_protostate;
	friend class sql_state;
};

#endif // HAS_ANALYZER
