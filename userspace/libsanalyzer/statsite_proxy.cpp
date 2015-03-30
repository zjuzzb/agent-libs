//
// Created by Luca Marturana on 30/03/15.
//
#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_int.h"
#include "statsite_proxy.h"

statsite_proxy::statsite_proxy(pair<FILE*, FILE*> const &fds):
		m_input_fd(fds.first),
		m_output_fd(fds.second)
{
	m_buffer[0] = '\0';
}

vector<statsd_metric::ptr_t> statsite_proxy::read_metrics()
{
	vector<statsd_metric::ptr_t> ret;
	auto metric = statsd_metric::create();
	uint64_t timestamp = 0;
	bool continue_read = true;
	if (m_buffer[0] == '\0')
	{
		continue_read = fgets(m_buffer, READ_BUFFER_SIZE, m_output_fd) != NULL;
	}
	while (continue_read)
	{
		bool parsed = metric->parse_line(m_buffer);
		if (parsed)
		{
			m_buffer[0] = '\0';
		}
		else
		{
			if (timestamp == 0)
			{
				timestamp = metric->timestamp();
			}
			ret.push_back(metric);

			metric = statsd_metric::create();
			metric->parse_line(m_buffer);
			if (timestamp < metric->timestamp())
			{
				break;
			}
		}
		continue_read = fgets(m_buffer, READ_BUFFER_SIZE, m_output_fd) != NULL;
	}
	return ret;
}