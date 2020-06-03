#pragma once
#include "analyzer_settings.h"  //sinsp_fdinfo_t really can't be foredeclared because of this
#include "feature_manager.h"
#include "type_config.h"

#include <bitset>
#include <stdint.h>

class sinsp_evt;
class sinsp_connection;
class yaml_configuration;

class port_list_config : public configuration_unit
{
public:
	/**
	 * Our yaml interface has three levels of keys possible. If a given
	 * value only requries fewer values, set the other strings to "". This
	 * constructor should register this object with the configuration_manager
	 * class.
	 *
	 * The value of this config is set to the default at construction, and
	 * so will be valid, even if the yaml file has not been parsed yet.
	 */
	port_list_config(const std::string& description, const std::string& key);

public:  // stuff for configuration_unit
	std::string value_to_string() const override;
	std::string value_to_yaml() const override;
	bool string_to_value(const std::string& value) override;
	void init(const yaml_configuration& raw_config) override;
	void post_init() override
	{ /*no-op*/
	}

public:  // other stuff
	using ports_set = std::bitset<std::numeric_limits<uint16_t>::max() + 1>;

	/**
	 * Returns a const reference to the current value of this type_config.
	 *
	 * @return the value of this config
	 */
	const ports_set& get_value() const;

private:
	ports_set m_data;
	uint32_t m_count;
};

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

	static port_list_config c_known_ports;
};

class protocol_base
{
public:
	virtual bool is_protocol(sinsp_evt* evt,
	                         sinsp_partial_transaction* trinfo,
	                         sinsp_partial_transaction::direction trdir,
	                         const uint8_t* buf,
	                         uint32_t buflen,
	                         uint16_t serverport) const = 0;
};

///////////////////////////////////////////////////////////////////////////////
// The protocol parser interface class
///////////////////////////////////////////////////////////////////////////////
class sinsp_protocol_parser
{
public:
	enum msg_type
	{
		MSG_NONE = 0,
		MSG_REQUEST,
		MSG_RESPONSE,
	};

	enum proto
	{
		PROTO_NONE = 0,
		PROTO_HTTP,
		PROTO_MYSQL,
		PROTO_POSTGRES,
		PROTO_MONGODB,
		PROTO_TLS
	};

	sinsp_protocol_parser();
	virtual ~sinsp_protocol_parser();
	virtual msg_type should_parse(sinsp_fdinfo_t* fdinfo,
	                              sinsp_partial_transaction::direction dir,
	                              bool is_switched,
	                              const char* buf,
	                              uint32_t buflen) = 0;
	virtual bool parse_request(const char* buf, uint32_t buflen) = 0;
	virtual bool parse_response(const char* buf, uint32_t buflen) = 0;
	virtual proto get_type() = 0;

	bool m_is_valid;
	bool m_is_req_valid;
};
