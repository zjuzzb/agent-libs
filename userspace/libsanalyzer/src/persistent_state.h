#pragma once
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <utility>
#include "draios.pb.h"
#include "analyzer_utils.h"
#include "sdc_internal.pb.h"
#include "type_config.h"

#include <gtest/gtest_prod.h>

// this class helps storying the kubernetes state into a file and vice-versa

class persistent_state
{
public:
	using get_ret_t = std::pair<bool, std::reference_wrapper<const draiosproto::k8s_state>>;
	enum class source_t : uint8_t
	{
		GLOBAL = 0,
		LOCAL
	};

	persistent_state(const persistent_state& other) = delete;
	persistent_state& operator =(const persistent_state& other) = delete;
	
	persistent_state(const std::string& store_path, uint16_t frequency_secs, uint32_t max_age_secs);
	persistent_state(persistent_state&& other);


	void store_global(uint64_t ts, const draiosproto::k8s_state& state);

	void store_local(uint64_t ts, const draiosproto::k8s_state& state);

	get_ret_t get_local(uint64_t ts);

	get_ret_t get_global(uint64_t ts);


private:
	FRIEND_TEST(infrastructure_state_test, persistent_state);
	static const std::vector<std::string> FILE_NAME;
	std::string m_store_path;
	uint16_t m_store_frequency;
	uint64_t m_last_dump_ts;
	uint64_t m_max_age;
	sdc_internal::persistent_state m_persistent_state_global;
	sdc_internal::persistent_state m_persistent_state_local;
	run_on_interval m_store_local;
	run_on_interval m_store_global;
	bool m_global_restored;
	bool m_local_restored;
	

	sdc_internal::persistent_state parse(source_t source) const;
	bool too_old(uint64_t ts, source_t source) const;
	void store(uint64_t, source_t, const draiosproto::k8s_state& state);
	bool restore(uint64_t ts, source_t source);
	std::string file_name(source_t source) const;
	void restore_global(uint64_t ts);
	void restore_local(uint64_t ts);
	get_ret_t get(source_t source) const;

};




class persistent_state_builder
{
public:
	static persistent_state build(const std::string& install_root)
	{
		std::string file_path;
		if(c_k8s_persistent_state_path.get_value() == c_k8s_persistent_state_path.get_default())
		{
			file_path = install_root + c_k8s_persistent_state_path.get_value();
		}
		else
		{
			file_path = c_k8s_persistent_state_path.get_value();
		}
		
		return persistent_state(file_path,
					c_k8s_persistent_state_frequency.get_value(),
					c_k8s_persistent_state_max_age.get_value());
	}
private:
	static type_config<std::string> c_k8s_persistent_state_path;
	static type_config<uint16_t> c_k8s_persistent_state_frequency;
	static type_config<uint64_t> c_k8s_persistent_state_max_age;
};
