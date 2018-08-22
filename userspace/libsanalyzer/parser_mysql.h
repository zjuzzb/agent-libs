///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
// Protocol specs can be found at 
// http://dev.mysql.com/doc/internals/en/client-server-protocol.html
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

#ifdef HAS_ANALYZER

#pragma once
#include "sqlparser.h"

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
// MYSQL parser
///////////////////////////////////////////////////////////////////////////////

class sinsp_mysql_parser : public sinsp_protocol_parser
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

	sinsp_sql_parser m_query_parser;

	friend class sinsp_protostate;
	friend class sql_state;
};

#endif // HAS_ANALYZER
