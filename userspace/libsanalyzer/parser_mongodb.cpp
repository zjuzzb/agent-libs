#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_int.h"
#include "parser_mongodb.h"
#include "sqlparser.h"

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
// Protocol specs can be found at
// http://docs.mongodb.org/meta-driver/latest/legacy/mongodb-wire-protocol/
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////


#ifdef HAS_ANALYZER

///////////////////////////////////////////////////////////////////////////////
// sinsp_mongodb_parser implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_mongodb_parser::sinsp_mongodb_parser():
	m_collection(NULL)
{
}

inline void sinsp_mongodb_parser::reset()
{
	m_parsed = false;
	m_is_valid = false;
	m_is_req_valid = false;
	m_collection_storage.clear();
	m_error_code = 0;
	m_msgtype = MONGODB_OP_NONE;
}

sinsp_mongodb_parser::proto sinsp_mongodb_parser::get_type()
{
	return sinsp_protocol_parser::PROTO_MONGODB;
}

sinsp_protocol_parser::msg_type sinsp_mongodb_parser::should_parse(sinsp_fdinfo_t* fdinfo,
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

bool sinsp_mongodb_parser::parse_request(char* buf, uint32_t buflen)
{
	if(buflen >= 16)
	{
		int32_t* opcode = (int32_t*)(buf+12);

		//
		// Do the parsing
		//
		switch(*opcode)
		{
		case WIRE_OP_INSERT:
			m_msgtype = MONGODB_OP_INSERT;
			break;
		case WIRE_OP_UPDATE:
			m_msgtype = MONGODB_OP_UPDATE;
			break;
		case WIRE_OP_DELETE:
			m_msgtype = MONGODB_OP_DELETE;
			break;
		case WIRE_OP_QUERY:
			m_msgtype = MONGODB_OP_QUERY;
		case WIRE_OP_GET_MORE:
			m_msgtype = MONGODB_OP_GET_MORE;
			break;
		}

		printf("MongoDB wire op is: %d\n", *opcode);
		printf("MongoDB op is: %d\n", m_msgtype);

		if (m_msgtype == MONGODB_OP_INSERT ||
			m_msgtype == MONGODB_OP_UPDATE ||
			m_msgtype == MONGODB_OP_DELETE ||
			m_msgtype == MONGODB_OP_QUERY ||
			m_msgtype == MONGODB_OP_GET_MORE)
		{
			// Extract collection name
			if (buflen >= 20)
			{
				char* start_collection = buf+20;
				for(int j = 0; j < buflen-20; ++j)
				{
					if (*start_collection == '.')
					{
						++start_collection;
						break;
					}
					++start_collection;
				}
				m_collection = m_collection_storage.copy(start_collection, buflen, 1);
				printf("MongoDB extracted collection: %s\n", m_collection);
			}
		}
		m_parsed = true;
		m_is_req_valid = true;

	}
	return true;
}

bool sinsp_mongodb_parser::parse_response(char* buf, uint32_t buflen)
{
	if(buflen >= 16)
	{
		int32_t* opcode = (int32_t*)(buf+12);

		if (*opcode == WIRE_OP_REPLY)
		{
			m_parsed=true;
			m_is_valid = true;
		}

	}

	return true;
}

#endif // HAS_ANALYZER
