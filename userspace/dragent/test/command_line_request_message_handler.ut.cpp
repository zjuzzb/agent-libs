#include <gtest.h>
#include "command_line_request_message_handler.h"
#include "async_command_handler.h"
#include "save_last_message_transmitter.h"

using namespace dragent;
using namespace test_helpers;

namespace
{

/**
 * A fake async command handler which immediately calls the 
 * callback with whatever was sent. 
 */
class echo_async_command_handler : public async_command_handler
{
public:
	using async_callback = std::function<void(const command_line_manager::response&)>;

	void async_handle_command(const command_line_permissions &permissions, const std::string &command, const async_callback& cb) override
	{
		command_line_manager::response resp;
		resp.first = command_line_manager::content_type::TEXT;
		resp.second = command;
		cb(resp);
	}
};

/**
 * A message handler wrapper for the echo_async_command_handler.
 */
class echo_command_line_request_message_handler : public command_line_request_message_handler
{

public:
	echo_command_line_request_message_handler(message_transmitter& transmitter,
						  const dragent_configuration& config) :
	    command_line_request_message_handler(std::make_shared<echo_async_command_handler>(),
						 transmitter,
						 config)
	{}
};

}

// Ensure that the message handler calls the command handler and fills in the 
// protobuf
TEST(command_line_request_message_handler_test, echo)
{
	// When we send a message to the message_handler, it will echo and then
	// go into the transmitter so we can validate
	save_last_message_transmitter<draiosproto::command_line_response> last_message;
	dragent_configuration config;
	echo_command_line_request_message_handler handler(last_message, config);

	const std::string customer_id = "deadbeef1234";
	const std::string key = "abcd";
	const std::string command = "book page turn";
	config.m_customer_id = customer_id;
	draiosproto::command_line_request proto;
	proto.set_key(key);
	proto.set_command(command);
	proto.mutable_permissions()->set_agent_status(true);
	proto.mutable_permissions()->set_network_calls_to_remote_pods(false);

	// Serialize the data into what the message handler expects
	std::string data;
	::google::protobuf::io::StringOutputStream stream(&data);
	::google::protobuf::io::GzipOutputStream gzstream(&stream);
	bool serialize_result = proto.SerializeToZeroCopyStream(&gzstream);
	gzstream.Close();
	ASSERT_TRUE(serialize_result);

	// Run the message handler
	const uint8_t* buf = reinterpret_cast<const uint8_t*>(data.data());
	bool result = handler.handle_message(draiosproto::message_type::COMMAND_LINE_REQUEST,
	                                     buf,
	                                     data.size());
	ASSERT_TRUE(result);
	ASSERT_EQ(draiosproto::message_type::COMMAND_LINE_RESPONSE, last_message.m_type);
	ASSERT_EQ(key, last_message.m_message.key());
	ASSERT_EQ(command, last_message.m_message.response());
	ASSERT_EQ(draiosproto::command_line_content_type::CLI_HTML_TEXT, last_message.m_message.content_type());
	ASSERT_EQ(customer_id, last_message.m_message.customer_id());
	ASSERT_TRUE(last_message.m_message.has_machine_id());
}

// Ensure that the message handler fails if it is the wrong message type.
TEST(command_line_request_message_handler_test, wrong_message_type)
{
	save_last_message_transmitter<draiosproto::command_line_response> last_message;
	dragent_configuration config;
	echo_command_line_request_message_handler handler(last_message, config);
	uint8_t* buf = nullptr;
	bool result = handler.handle_message(draiosproto::message_type::AUDIT_TAP,
					     buf,
					     0);
	ASSERT_FALSE(result);
}

// Ensure that the message handler fails if there is no command handler.
TEST(command_line_request_message_handler_test, null_command_handler)
{
	save_last_message_transmitter<draiosproto::command_line_response> last_message;
	dragent_configuration config;
	// Null message handler
	command_line_request_message_handler handler(std::shared_ptr<async_command_handler>(nullptr),
						     last_message,
						     config);
	const std::string customer_id = "deadbeef1234";
	const std::string key = "abcd";
	const std::string command = "book page turn";
	config.m_customer_id = customer_id;
	draiosproto::command_line_request proto;
	proto.set_key(key);
	proto.set_command(command);

	// Serialize the data into what the message handler expects
	std::string data;
	::google::protobuf::io::StringOutputStream stream(&data);
	::google::protobuf::io::GzipOutputStream gzstream(&stream);
	bool serialize_result = proto.SerializeToZeroCopyStream(&gzstream);
	gzstream.Close();
	ASSERT_TRUE(serialize_result);

	// Run the message handler
	const uint8_t* buf = reinterpret_cast<const uint8_t*>(data.data());
	bool result = handler.handle_message(draiosproto::message_type::COMMAND_LINE_REQUEST,
	                                     buf,
	                                     data.size());
	ASSERT_TRUE(result);
	ASSERT_EQ(key, last_message.m_message.key());
	ASSERT_EQ(draiosproto::command_line_content_type::CLI_ERROR, last_message.m_message.content_type());
	ASSERT_EQ("Agent CLI is disabled in agent configuration.", last_message.m_message.response());
	ASSERT_EQ(customer_id, last_message.m_message.customer_id());
	ASSERT_TRUE(last_message.m_message.has_machine_id());

}

