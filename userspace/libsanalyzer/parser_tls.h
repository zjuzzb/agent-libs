//
// Created by Luca Marturana on 14/09/15.
//

#pragma once

class sinsp_tls_parser: public sinsp_protocol_parser
{
public:
	explicit sinsp_tls_parser() = default;
	virtual ~sinsp_tls_parser() = default;
	virtual sinsp_protocol_parser::msg_type should_parse(sinsp_fdinfo_t* fdinfo,
														 sinsp_partial_transaction::direction dir,
														 bool is_switched,
														 char* buf, uint32_t buflen) override;

	virtual bool parse_request(char* buf, uint32_t buflen) override;

	virtual bool parse_response(char* buf, uint32_t buflen) override;

	virtual sinsp_protocol_parser::proto get_type();
};