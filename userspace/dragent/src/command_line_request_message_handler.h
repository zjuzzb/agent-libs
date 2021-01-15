#pragma once

#include "configuration.h"
#include "connection_manager.h"
#include "command_line_manager.h"
#include "command_line_permissions.h"
#include "async_command_handler.h"
#include "draios.pb.h"

namespace dragent
{

/**
 * Handles messages of type COMMAND_LINE_REQUEST that the 
 * connection_manager receives from the backend. 
 */
class command_line_request_message_handler : public connection_manager::message_handler
{
public:
	command_line_request_message_handler(const std::shared_ptr<async_command_handler> &handler,
					     message_transmitter& transmitter,
					     const dragent_configuration& configuration);

	/**
	 * Pass the message to the async_command_handler and 
	 * asynchronously transmit a response. 
	 */
	bool handle_message(const draiosproto::message_type,
	                    const uint8_t* buffer,
	                    size_t buffer_size) override;
private:
	command_line_permissions to_permissions(const draiosproto::command_line_permissions& msg);
	void send_response(const std::string& key,
                           const command_line_manager::response& cmd_response);

	std::shared_ptr<async_command_handler> m_handler;
	message_transmitter& m_transmitter;
	const dragent_configuration& m_configuration;
};

} // namespace dragent
