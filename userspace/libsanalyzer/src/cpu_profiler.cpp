#include "cpu_profiler.h"
#include "type_config.h"
#include "utils/profiler.h"
#include "utils.h"

type_config<bool> c_dragent_cpu_profile(false,
					"Create dragent cpu profiles and save to the log directory",
					"dragent_cpu_profile_enabled");

type_config<int32_t> c_dragent_cpu_profile_seconds(
	120,
	"The number of seconds to collect data for a single cpu profile",
	"dragent_profile_time_seconds");

type_config<int32_t> c_dragent_cpu_profile_total_profiles(
	30,
	"The total number of cpu profiles to collect before overwriting old profiles",
	"dragent_total_profiles");

cpu_profiler::cpu_profiler(const std::string&& filename_pattern):
	m_filename_pattern(filename_pattern),
	m_trace_enabled(false),
	m_trace_id(0),
	m_last_rotated(0)
{
}

void cpu_profiler::start()
{
	m_trace_enabled = true;
	std::string filename = m_filename_pattern + std::to_string(m_trace_id);
	utils::profiler::start(filename);
	m_last_rotated = sinsp_utils::get_current_time_ns();
}

void cpu_profiler::tick()
{
	if(!c_dragent_cpu_profile.get_value())
	{
		return;
	}

	if(!m_trace_enabled)
	{
		start();
		return;
	}

	const uint64_t now = sinsp_utils::get_current_time_ns();
	if((now - m_last_rotated) / 1000000000 > c_dragent_cpu_profile_seconds.get_value())
	{
		utils::profiler::stop();
		m_trace_id++;
		m_trace_id %= c_dragent_cpu_profile_total_profiles.get_value();
		start();
	}
}

cpu_profiler::~cpu_profiler()
{
	if (m_trace_enabled)
	{
		utils::profiler::stop();
	}
}
