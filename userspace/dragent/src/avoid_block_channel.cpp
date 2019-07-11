/**
 * @file
 *
 * Implementation of avoid_block_channel.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "avoid_block_channel.h"
#include "common_logger.h"
#include "user_event.h"
#include "user_event_logger.h"
#include "utils.h"
#include <iostream>
#include <string>
#include <sstream>
#include <unordered_map>
#include <sys/statvfs.h>
#include <Poco/FileChannel.h>

avoid_block_channel::avoid_block_channel(
		const Poco::AutoPtr<Poco::FileChannel>& file_channel,
		const std::string& machine_id):
	m_file_channel(file_channel),
	m_machine_id(machine_id),
	m_error_event_sent(false)
{
}

void avoid_block_channel::log(const Poco::Message &message)
{
	try
	{
		m_file_channel->log(message);
		m_error_event_sent = false;
	}
	catch (const Poco::WriteFileException& ex)
	{
		std::cerr << "Cannot write to draios.log" << std::endl;
		if(g_log && !m_error_event_sent)
		{
			// set immediately to prevent many threads racing in here
			m_error_event_sent = true;
			std::string fname = m_file_channel->getProperty("path");
			struct statvfs buf;
			if(0 == statvfs(fname.c_str(), &buf))
			{
				std::ostringstream os;
				os << "Logger (" << fname << "): [" << ex.displayText() << ']' << std::endl <<
					"disk free=" << buf.f_bsize * buf.f_bfree / 1024 << " kb";
				std::unordered_map<std::string, std::string> tags{{"source", "dragent"}};

				user_event_logger::log(
						sinsp_user_event::to_string(
							get_epoch_utc_seconds_now(),
							"DragentLoggerError",
							os.str(),
							event_scope("host.mac", m_machine_id),
							move(tags)),
						user_event_logger::SEV_EVT_ERROR);
			}
		}
	}
}

void avoid_block_channel::open()
{
	m_file_channel->open();
}

void avoid_block_channel::close()
{
	m_file_channel->close();
}
