#include "app_checks_proxy.h"
#include "common_logger.h"

#include <zlib.h>

COMMON_LOGGER();

void app_checks_proxy::send_get_metrics_cmd_sync(const vector<app_process> &processes, const vector<prom_process>& prom_procs, const prometheus_conf &prom_conf)
{
	Json::Value procs = Json::Value(Json::arrayValue);
	for(const auto& p : processes)
	{
		procs.append(p.to_json());
	}
	Json::Value promps = Json::Value(Json::arrayValue);
#ifndef CYGWING_AGENT
	for(const auto& p : prom_procs)
	{
		promps.append(p.to_json(prom_conf));
	}
#endif

	Json::Value command;
	command["processes"] = procs;
	command["prometheus"] = promps;
	string data = m_json_writer.write(command);
	// This following command publishes entire app_check config in logs (including username, password)
	// Filter it out for now. 
	//LOG_DEBUG("Send to sdchecks: %s", data.c_str());
	m_outqueue.send(data);
}

app_checks_proxy::raw_metric_map_t app_checks_proxy::read_metrics(const metric_limits::sptr_t& ml, uint64_t timeout_sec)
{
	raw_metric_map_t ret;
	try
	{
		uint32_t uncompressed_size = 0;
		auto buf = m_inqueue.receive(timeout_sec);
		std::vector<Bytef> uncompressed_msg;

		if(buf.empty())
		{
			return ret;
		}

		uint8_t version = buf[0];
		if(version != PROTOCOL_VERSION)
		{
			LOG_ERROR("Unsupported sdchecks response version %d", version);
			return ret;
		}

		// zero length might be a timeout, non-zero and < 5 is a bug
		ASSERT(buf.size() >= sizeof(uint32_t) + 1);

		memcpy(&uncompressed_size, &buf[1], sizeof(uint32_t));
		uncompressed_size = ntohl(uncompressed_size);
		LOG_DEBUG("Received %lu from sdchecks bytes, uncompressed length %u", buf.size(), uncompressed_size);

		if(buf.size() >= MAX_COMPRESSED_SIZE || uncompressed_size > MAX_UNCOMPRESSED_SIZE)
		{
			LOG_ERROR("sdchecks response too large (compressed %zu, uncompressed %u)", buf.size(), uncompressed_size);
			return ret;
		}

		const char* start = &buf[0] + 1 + sizeof(uint32_t);
		unsigned long len = buf.size() - 1 - sizeof(uint32_t);

		if (uncompressed_size > 0)
		{
			unsigned long u = uncompressed_size;
			uncompressed_msg.reserve(u);
			int res = uncompress(&(uncompressed_msg[0]), &u, (const Bytef*)start, len);
			LOG_DEBUG("Uncompressed to %u bytes, res=%d", uncompressed_size, res);
			if (res != Z_OK)
			{
				LOG_ERROR( "uncompress error %d", res);
				return ret;
			}
			start = reinterpret_cast<char*>(&uncompressed_msg[0]);
			len = uncompressed_size;
		}

		if(len == 0)
		{
			LOG_WARNING("Received an empty message from sdchecks (compressed size %ld)", buf.size());
			return ret;
		}

		LOG_DEBUG("Received from sdchecks: %lu bytes", len);
		Json::Value response_obj;
		if(m_json_reader.parse(start, start+len, response_obj, false))
		{
			auto proc_metrics = [](const Json::Value& obj, app_check_data::check_type t, const metric_limits::sptr_t& ml, raw_metric_map_t &ret) {
				for(const auto& process : obj)
				{
					app_check_data data(process, ml);
					// only add if there are metrics or services
					if(!data.metrics().empty() || !data.services().empty() || data.total_metrics())
					{
						data.set_type(t);
						auto pid = data.pid();
						auto name = data.name();
						ret[pid][name] = std::make_shared<app_check_data>(std::move(data));
					}
				}
			};
			if (response_obj.isMember("processes"))
			{
				const auto& resp_obj = response_obj["processes"];
				proc_metrics(resp_obj, app_check_data::check_type::APPCHECK, ml, ret);
			}
			if (response_obj.isMember("prometheus"))
			{
				const auto& resp_obj = response_obj["prometheus"];
				proc_metrics(resp_obj, app_check_data::check_type::PROMETHEUS, ml, ret);
			}
		}
		else
		{
			LOG_ERROR("app_checks_proxy::read_metrics: JSON parsing error:");
			std::string msg(start, len);
			LOG_DEBUG("%s", msg.c_str());
		}
	}
	catch(std::exception& ex)
	{
		LOG_ERROR("app_checks_proxy::read_metrics error: %s", ex.what());
	}
	return ret;
}


void app_checks_proxy::refresh_metrics_sync(uint64_t flush_time_sec, uint64_t timeout_sec)
{
	auto app_metrics = read_metrics(m_metric_limits, timeout_sec);
	auto my_app_metrics = m_app_metrics.lock();
	for(auto it = my_app_metrics->begin(); it != my_app_metrics->end();)
	{
		for(auto it2 = it->second.begin(); it2 != it->second.end();)
		{
			if(flush_time_sec > it2->second->expiration_ts() + APP_METRICS_EXPIRATION_TIMEOUT_S)
			{
				LOG_DEBUG("Wiping expired app metrics for pid %d,%s", it->first, it2->first.c_str());
				it2 = it->second.erase(it2);
			}
			else
			{
				++it2;
			}
		}
		if(it->second.empty())
		{
			it = my_app_metrics->erase(it);
		}
		else
		{
			++it;
		}
	}
	for(auto& item : app_metrics)
	{
		for(auto& met : item.second)
		{
			(*my_app_metrics)[item.first][met.first] = move(met.second);
		}
	}

}

void app_checks_proxy::refresh_metrics(uint64_t flush_time_sec, uint64_t timeout_sec)
{
	if(!m_threaded)
	{
		refresh_metrics_sync(flush_time_sec, timeout_sec);
	}
}


bool app_checks_proxy::have_metrics_for_pid(uint64_t pid) const
{
	auto my_app_metrics = m_app_metrics.lock();
	auto datamap_it = my_app_metrics->find(pid);
	if(datamap_it == my_app_metrics->end())
	{
		return false;
	}

	for(const auto& app_data : datamap_it->second)
	{
		if(app_data.second->total_metrics() > 0)
		{
			return true;
		}
	}

	return false;
}

bool app_checks_proxy::have_prometheus_metrics_for_pid(uint64_t pid, uint64_t flush_time_sec) const
{
	auto my_app_metrics = m_app_metrics.lock();
	auto datamap_it = my_app_metrics->find(pid);
	if(datamap_it == my_app_metrics->end())
	{
		return false;
	}

	for(const auto& app_data : datamap_it->second)
	{
		if((app_data.second->type() == app_check_data::check_type::PROMETHEUS) &&
		   (app_data.second->expiration_ts() > flush_time_sec))
		{
			return true;
		}
	}

	return false;
}

bool app_checks_proxy::have_app_check_metrics_for_pid(uint64_t pid, uint64_t flush_time_sec, const std::string& name) const
{
	auto my_app_metrics = m_app_metrics.lock();
	auto datamap_it = my_app_metrics->find(pid);
	if(datamap_it == my_app_metrics->end())
	{
		return false;
	}

	auto app_check = datamap_it->second.find(name);
	if(app_check == datamap_it->second.end())
	{
		return false;
	}

	return app_check->second->expiration_ts() > flush_time_sec;
}

void app_checks_proxy::send_get_metrics_cmd(std::vector<app_process> processes,
					    std::vector<prom_process> prom_procs, const prometheus_conf* conf)
{
	if(m_threaded)
	{
		app_check_request req = {
			std::move(processes),
			std::move(prom_procs),
			conf
		};

		LOG_DEBUG("[app_checks_proxy] putting request");
		if(!m_request_queue.put(req))
		{
			LOG_INFO("[app_checks_proxy] queue full");
		}
	}
	else
	{
		send_get_metrics_cmd_sync(processes, prom_procs, *conf);
	}
}

void app_checks_proxy::do_run()
{
	ASSERT(m_threaded);
	while(heartbeat())
	{
		app_check_request req;
		LOG_DEBUG("[app_checks_proxy] getting request");
		if(m_request_queue.get(&req, 1000))
		{
			LOG_DEBUG("[app_checks_proxy] got request, sending to sdchecks");
			send_get_metrics_cmd_sync(req.processes, req.prom_procs, *req.conf);
			LOG_DEBUG("[app_checks_proxy] sent request, calling refresh_metrics");
			refresh_metrics_sync(time(nullptr), 1);
			LOG_DEBUG("[app_checks_proxy] refresh_metrics done");
		}
		LOG_DEBUG("[app_checks_proxy] timeout, no request");
	}
}
