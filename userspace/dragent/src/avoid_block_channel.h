/**
 * @file
 *
 * Interface to avoid_block_channel.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include <atomic>
#include <string>
#include <Poco/AutoPtr.h>
#include <Poco/Channel.h>
#include <Poco/Message.h>

namespace Poco
{
class FileChannel;
}

class avoid_block_channel : public Poco::Channel
{
public:
	avoid_block_channel(const Poco::AutoPtr<Poco::FileChannel>& file_channel,
	                    const std::string& machine_id);

	virtual void log(const Poco::Message& message) override;
	virtual void open() override;
	virtual void close() override;

private:
	Poco::AutoPtr<Poco::FileChannel> m_file_channel;
	const std::string m_machine_id;
	std::atomic<bool> m_error_event_sent;
};

