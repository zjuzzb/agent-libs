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

class sinsp_mongodb_parser : public sinsp_protocol_parser
{
public:
	enum msg_type
	{
		MONGODB_OP_NONE = 0,
		MONGODB_OP_INSERT = 1,
		MONGODB_OP_UPDATE = 2,
		MONGODB_OP_DELETE = 3,
		MONGODB_OP_QUERY = 4,
		MONGODB_OP_GET_MORE = 5,
		MONGODB_OP_KILL_CURSORS = 6,
		MONGODB_OP_FIND = 7,
		MONGODB_OP_AGGREGATE = 8,
		MONGODB_OP_COMMAND = 9,
	};

	sinsp_mongodb_parser();
	sinsp_protocol_parser::msg_type should_parse(sinsp_fdinfo_t* fdinfo,
		sinsp_partial_transaction::direction dir,
		bool is_switched,
		char* buf, uint32_t buflen);
	bool parse_request(char* buf, uint32_t buflen);
	bool parse_response(char* buf, uint32_t buflen);
	proto get_type();

	char* m_collection;
	uint16_t m_error_code;
	msg_type m_msgtype;

private:
	enum wire_opcodes
	{
		WIRE_OP_NONE = 0,
		WIRE_OP_REPLY = 1,
		WIRE_OP_MSG = 1000,
		WIRE_OP_UPDATE = 2001,
		WIRE_OP_INSERT = 2002,
		WIRE_OP_QUERY = 2004,
		WIRE_OP_GET_MORE = 2005,
		WIRE_OP_DELETE = 2006,
		WIRE_OP_KILL_CURSORS = 2007
	};

	inline void reset();

	sinsp_autobuffer m_collection_storage;
	bool m_parsed;

	char* m_error_message;
};

#endif // HAS_ANALYZER
