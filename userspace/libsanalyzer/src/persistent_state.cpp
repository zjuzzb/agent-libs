#include "persistent_state.h"
#include "libsanalyzer_exceptions.h"
#include "common_logger.h"
#include <fstream>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <google/protobuf/text_format.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <Poco/File.h>
#include <Poco/Path.h>
#include <sstream>


COMMON_LOGGER();

persistent_state::persistent_state(const std::string& store_path, uint16_t frequency_secs, uint32_t max_age_secs)
	: m_store_path(store_path),
	  m_store_frequency(frequency_secs),
	  m_max_age(max_age_secs * NSECS_PER_SEC),
	  m_store_local(frequency_secs * NSECS_PER_SEC),
	  m_store_global(frequency_secs * NSECS_PER_SEC),
	  m_global_restored(false),
	  m_local_restored(false)
{
	struct stat st;
	int ret = stat(store_path.c_str(), &st);

	bool exists = ret == 0;

	if(!exists)
	{
		// Try to create the directory if it does not exist
		try
		{
			auto path = Poco::Path(store_path).makeAbsolute();
			path.makeDirectory();
			Poco::File(Poco::Path(store_path).makeAbsolute()).createDirectories();
		}
		catch(const std::exception& ex)
		{
			LOG_ERROR("%s", ex.what());
		}
	}
}

persistent_state::persistent_state(persistent_state&& other) :
	m_store_path(std::move(other.m_store_path)),
	m_store_frequency(std::move(other.m_store_frequency)),
	m_last_dump_ts(other.m_last_dump_ts),
	m_max_age(std::move(other.m_max_age)),
	m_persistent_state_global(std::move(other.m_persistent_state_global)),
	m_persistent_state_local(std::move(other.m_persistent_state_local)),
	m_store_local(std::move(other.m_store_local)),
	m_store_global(std::move(other.m_store_global)),
	m_global_restored(std::move(other.m_global_restored)),
	m_local_restored(std::move(other.m_local_restored))
{
}


void persistent_state::store_global(uint64_t ts, const draiosproto::k8s_state &state)
{
	store(ts, source_t::GLOBAL, state);
}

void persistent_state::store_local(uint64_t ts, const draiosproto::k8s_state &state)
{
	store(ts, source_t::LOCAL, state);
}

void persistent_state::store(uint64_t ts, source_t source, const draiosproto::k8s_state& state)
{
	run_on_interval& r = source == source_t::GLOBAL ? m_store_global : m_store_local;
	
	r.run( [this, ts, &source, &state]()
	       {
		       std::string file_name = m_store_path + "/" + FILE_NAME[static_cast<int>(source)];
		       std::ofstream f(file_name, std::ios_base::trunc|std::ios_base::out|std::ios_base::binary);

		       if(!f.is_open())
		       {
		       	       LOG_DEBUG("unable to open file %s", file_name.c_str());
		       }
		       else
		       {
			       sdc_internal::persistent_state ps;
			       ps.set_ts(ts);

			       ps.mutable_state()->CopyFrom(state);

			       ps.SerializeToOstream(&f);
			       f.close();

			       LOG_DEBUG("orchestrator %s state stored on %s",
			                 source == source_t::GLOBAL ? "global" : "local",
			                 file_name.c_str());

			       f.close();
		       }
	       },ts);
}

std::string persistent_state::file_name(source_t source) const
{
	return m_store_path + "/" + FILE_NAME[static_cast<int>(source)];
}

sdc_internal::persistent_state persistent_state::parse(source_t source) const
{
	auto f_name = file_name(source);
	std::fstream f(f_name, std::ios::in | std::ios::binary);

	if(!f.is_open())
	{
		throw persistent_state_error("unable to open dump file " + f_name);
	}


	sdc_internal::persistent_state ps;

	if(!ps.ParseFromIstream(&f))
	{
		throw persistent_state_error("unable to parse dump file");
	}

	return ps;
}

void persistent_state::restore_global(uint64_t ts)
{
	// Prevent from calling restore many times, if an error already occured
	// or we already have the backup
	static bool got_error = false;
	if(!m_global_restored && !got_error)
	{
		m_global_restored = !(got_error = !restore(ts, source_t::GLOBAL));
	}
}

void persistent_state::restore_local(uint64_t ts)
{
	// Prevent from calling restore many times, if an error already occured
	// or we already have the backup
	static bool got_error = false;
	if(!m_local_restored && !got_error)
	{
		m_local_restored = !(got_error = !restore(ts, source_t::LOCAL));
	}
}

bool persistent_state::restore(uint64_t ts, source_t source)
{
	auto f_name = file_name(source);
	if(too_old(ts, source))
	{
		LOG_DEBUG("Backup file %s is too old or does not exist. Skip restoring it", f_name.c_str());
		return false;
	}

	sdc_internal::persistent_state ps;
	try
	{
		ps = parse(source);

		sdc_internal::persistent_state& restored = (source == source_t::GLOBAL ? m_persistent_state_global : m_persistent_state_local);


		restored.mutable_state()->CopyFrom(ps.state());
		LOG_DEBUG("orchestrator state loaded from file %s", f_name.c_str());

		return true;
	}
	catch(const persistent_state_error& err)
	{
		LOG_WARNING("%s", err.what());
		return false;
	}
}

persistent_state::get_ret_t persistent_state::get_local(uint64_t ts)
{
	restore_local(ts);
	return get(persistent_state::source_t::LOCAL);
}

persistent_state::get_ret_t persistent_state::get_global(uint64_t ts)
{
	restore_global(ts);
	return get(persistent_state::source_t::GLOBAL);
}

bool persistent_state::too_old(uint64_t ts, source_t source) const
{
	try
	{
		auto pis = parse(source);
		return ts - pis.ts() > m_max_age;
	}
	catch(const std::exception& ex)
	{
		return true;
	}
}

persistent_state::get_ret_t persistent_state::get(persistent_state::source_t source) const
{
	
	const draiosproto::k8s_state& state = source == persistent_state::source_t::GLOBAL ? m_persistent_state_global.state() : m_persistent_state_local.state();

	bool ret = true;

	if ( (source == persistent_state::source_t::GLOBAL && !m_global_restored) ||
	     (source == persistent_state::source_t::LOCAL && !m_local_restored))
	{
		ret = false;
	}

	return std::make_pair(ret, std::cref(state));
}

const std::vector<std::string> persistent_state::FILE_NAME = {
	"global.dams",
	"local.dams"
};


type_config<std::string> persistent_state_builder::c_k8s_persistent_state_path("/infrastate",
						     "infustructure state backup file path",
						     "k8s_infrastate_backup_path");
type_config<uint16_t> persistent_state_builder::c_k8s_persistent_state_frequency(10,
						       "seconds between to successive infra state backups",
						       "k8s_infrastate_backup_frequency");
type_config<uint64_t> persistent_state_builder::c_k8s_persistent_state_max_age(60,
						     "Do not restore the infrastate backup if it is older than these seconds",
						     "k8s_infrastate_max_age");
