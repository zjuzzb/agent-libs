///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
// Protocol specs can be found at
// http://docs.mongodb.org/meta-driver/latest/legacy/mongodb-wire-protocol/
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

#ifdef HAS_ANALYZER

#pragma once

///////////////////////////////////////////////////////////////////////////////
// MongoDB parser
///////////////////////////////////////////////////////////////////////////////

class sinsp_mongodb_parser : sinsp_protocol_parser
{
public:
	enum msg_type
	{
		MT_NONE = 0,
		MT_REPLY = 1,
		MT_MSG = 1000,
		MT_UPDATE = 2001,
		MT_INSERT = 2002,
		MT_QUERY = 2004,
		MT_GET_MORE = 2005,
		MT_DELETE = 2006,
		MT_KILL_CURSORS = 2007
	};

	sinsp_mongodb_parser();
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


	friend class sinsp_protostate;
};

#endif // HAS_ANALYZER
