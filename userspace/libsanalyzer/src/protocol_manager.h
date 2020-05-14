#pragma once
#include "analyzer_settings.h"  //sinsp_fdinfo_t really can't be foredeclared because of this
#include "feature_manager.h"

#include <stdint.h>

class sinsp_evt;
class sinsp_connection;

class protocol_manager : public feature_base
{
private:
	static protocol_manager* s_protocol_manager;

public:
	static protocol_manager& instance();

	protocol_manager();

	static void protocol_event_received(sinsp_evt* evt,
	                                    int64_t fd,
	                                    sinsp_fdinfo_t* fdinfo,
	                                    char* data,
	                                    uint32_t original_len,
	                                    uint32_t len,
	                                    sinsp_connection* connection,
	                                    sinsp_partial_transaction::direction trdir,
	                                    sinsp_analyzer& analyzer);

	static sinsp_partial_transaction::type detect_proto(sinsp_evt* evt,
	                                                    sinsp_partial_transaction* trinfo,
	                                                    sinsp_partial_transaction::direction trdir,
	                                                    uint8_t* buf,
	                                                    uint32_t buflen);
};
