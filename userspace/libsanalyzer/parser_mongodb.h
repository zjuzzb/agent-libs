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
	//
	// MongoDB operation reported to metrics
	//
	enum opcode
	{
		MONGODB_OP_NONE = 0,
		MONGODB_OP_INSERT = 1,
		MONGODB_OP_UPDATE = 2,
		MONGODB_OP_DELETE = 3,
		MONGODB_OP_GET_MORE = 4,
		MONGODB_OP_KILL_CURSORS = 5,
		MONGODB_OP_FIND = 6,
		MONGODB_OP_AGGREGATE = 7,
		MONGODB_OP_COMMAND = 8,
		MONGODB_OP_COUNT = 9,
		MONGODB_OP_DISTINCT = 10,
		MONGODB_OP_MAP_REDUCE = 11,
		MONGODB_OP_GEO_NEAR = 12,
		MONGODB_OP_GEO_SEARCH = 13,
		MONGODB_OP_FIND_AND_MODIFY = 14,
	};

	sinsp_mongodb_parser();
	sinsp_protocol_parser::msg_type should_parse(sinsp_fdinfo_t* fdinfo,
						     sinsp_partial_transaction::direction dir,
						     bool is_switched,
						     const char* buf,
						     uint32_t buflen);
	bool parse_request(const char* buf, uint32_t buflen);
	bool parse_response(const char* buf, uint32_t buflen);
	proto get_type();

	char* m_collection;
	uint16_t m_error_code;
	opcode m_opcode;

private:
	//
	// MongoDB operations defined on the wire
	// protocol
	//
	enum wire_opcode
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
	wire_opcode m_wireopcode;
	inline void reset();

	sinsp_autobuffer m_collection_storage;
	sinsp_autobuffer m_reassembly_buf;
	bool m_parsed;

	static const uint32_t commands_size;
	static const char* commands[];
	static const uint32_t commands_sizes_map[];
	static const opcode commands_to_opcode[];
};

#endif // HAS_ANALYZER
