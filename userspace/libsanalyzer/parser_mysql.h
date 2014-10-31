///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
// Protocol specs can be found at 
// http://dev.mysql.com/doc/internals/en/client-server-protocol.html
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

#ifdef HAS_ANALYZER

#pragma once

///////////////////////////////////////////////////////////////////////////////
// Offsets
///////////////////////////////////////////////////////////////////////////////
#define MYSQL_OFFSET_SEQ_ID 3
#define MYSQL_OFFSET_OPCODE 4
#define MYSQL_OFFSET_STATEMENT 5
#define MYSQL_OFFSET_UNAME 36

#define MYSQL_OFFSET_STATUS 4
#define MYSQL_OFFSET_ERROR_CODE 5
#define MYSQL_OFFSET_ERROR_MESSAGE 13

///////////////////////////////////////////////////////////////////////////////
// Opcodes
///////////////////////////////////////////////////////////////////////////////
#define MYSQL_OPCODE_QUERY 3

///////////////////////////////////////////////////////////////////////////////
// Capabilities
///////////////////////////////////////////////////////////////////////////////
#define CAP_LONG_PASSWORD    1       // new more secure passwords
#define CAP_FOUND_ROWS       2       // Found instead of affected rows
#define CAP_LONG_FLAG        4       // Get all column flags
#define CAP_CONNECT_WITH_DB  8       // One can specify db on connect
#define CAP_NO_SCHEMA        16      // Don't allow database.table.column
#define CAP_COMPRESS         32      // Can use compression protocol
#define CAP_ODBC             64      // Odbc client
#define CAP_LOCAL_FILES      128     // Can use LOAD DATA LOCAL
#define CAP_IGNORE_SPACE     256     // Ignore spaces before '('
#define CAP_PROTOCOL_41      512     // New 4.1 protocol
#define CAP_INTERACTIVE      1024    // This is an interactive client
#define CAP_SSL              2048    // Switch to SSL after handshake
#define CAP_IGNORE_SIGPIPE   4096    // IGNORE sigpipes
#define CAP_TRANSACTIONS     8192    // Client knows about transactions
#define CAP_RESERVED         16384   // Old flag for 4.1 protocol 
#define CAP_SECURE_CONNECTION 32768  // New 4.1 authentication
#define CAP_MULTI_STATEMENTS 65536   // Enable/disable multi-stmt support
#define CAP_MULTI_RESULTS    131072  // Enable/disable multi-results

///////////////////////////////////////////////////////////////////////////////
// HTTP parser
///////////////////////////////////////////////////////////////////////////////
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

class sinsp_mysql_parser : sinsp_protocol_parser
{
public:
	enum msg_type
	{
		MT_NONE = 0,
		MT_LOGIN,
		MT_QUERY,
	};

	sinsp_mysql_parser();
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
};

#endif // HAS_ANALYZER
