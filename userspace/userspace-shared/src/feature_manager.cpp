#include "common.pb.h"
#include "common_logger.h"
#include "configuration_manager.h"
#include "feature_manager.h"
namespace
{
COMMON_LOGGER();

feature_manager* s_instance = nullptr;

type_config<std::string> c_agent_mode("monitor",
                                      "the agent mode to execute in.",
                                      "feature",
                                      "mode");

}  // namespace

const feature_manager::agent_variant_container feature_manager::variant_definitions[] = {
    {feature_manager::AGENT_VARIANT_TRADITIONAL, "traditional"},
    {feature_manager::AGENT_VARIANT_AGENTONE, "agentone"},
    {feature_manager::AGENT_VARIANT_AGENTINO, "agentino"}};

static_assert(feature_manager::agent_variant::AGENT_VARIANT_COUNT ==
                  sizeof(feature_manager::variant_definitions) /
                      sizeof(feature_manager::variant_definitions[0]),
              "not all agent variants definined");


const feature_manager::agent_mode_container feature_manager::mode_definitions[] = {
    {feature_manager::AGENT_MODE_NONE, "none", {}, {}},
    {feature_manager::AGENT_MODE_MONITOR,
     "monitor",
     {STATSD,
      JMX,
      APP_CHECKS,
      COINTERFACE,
      DRIVER,
      FULL_SYSCALLS,
      PROTOCOL_STATS,
      HTTP_STATS,
      NETWORK_BREAKDOWN,
      MONITOR},
     {{"http.url_table_size", config_placeholder_impl<uint32_t>::build(0u)}}},
    {feature_manager::AGENT_MODE_MONITOR_LIGHT,
     "monitor_light",
     {MONITOR},
     {{"http.url_table_size", config_placeholder_impl<uint32_t>::build(0u)}}},
    {feature_manager::AGENT_MODE_ESSENTIALS,
     "essentials",
     {STATSD, JMX, APP_CHECKS, COINTERFACE, DRIVER, FULL_SYSCALLS, MONITOR},
     {{"http.url_table_size", config_placeholder_impl<uint32_t>::build(0u)}}},
    {feature_manager::AGENT_MODE_TROUBLESHOOTING,
     "troubleshooting",
     {STATSD,
      JMX,
      APP_CHECKS,
      COINTERFACE,
      DRIVER,
      FULL_SYSCALLS,
      PROTOCOL_STATS,
      NETWORK_BREAKDOWN,
      FILE_BREAKDOWN,
      HTTP_STATS,
      MYSQL_STATS,
      POSTGRES_STATS,
      MONGODB_STATS,
      MONITOR},
     {}},
    {feature_manager::AGENT_MODE_SECURE,
     "secure",
     {COINTERFACE, DRIVER, FULL_SYSCALLS},
     {{"10s_flush_enable", config_placeholder_impl<bool>::build(true)}}},
    // Note that "DRIVER" feature is really misnamed....it really just means event source
    {feature_manager::AGENT_MODE_AGENTINO,
     "agentino",
     {SECURE, MEMDUMP, DRIVER, FULL_SYSCALLS},
     {
         {"security.actions_enabled", config_placeholder_impl<bool>::build(true)},
         {"ssl_verify_certificate", config_placeholder_impl<bool>::build(false)},
         {"security.k8s_audit_server_enabled", config_placeholder_impl<bool>::build(false)},
         {"sinsp.thread_purge_interval_s", config_placeholder_impl<uint32_t>::build(2 * 60)},
         {"sinsp.thread_timeout_s", config_placeholder_impl<uint32_t>::build(5 * 60)},
         {"max_thread_table_size", config_placeholder_impl<uint32_t>::build(20000)},
     }},
    {feature_manager::AGENT_MODE_AGENTONE, "agentone", {SECURE, DRIVER, FULL_SYSCALLS}, {}}};

static_assert(feature_manager::agent_mode::AGENT_MODE_COUNT ==
                  sizeof(feature_manager::mode_definitions) /
                      sizeof(feature_manager::mode_definitions[0]),
              "not all agent modes definined");

// clang-format off
const feature_manager::agent_feature_container feature_manager::feature_configs[] =
{
	{PROMETHEUS,           "prometheus",           feature_config(false,
	                                                              "enable prom",
	                                                              "prometheus",
	                                                              "enabled")},
	{STATSD,               "statsd",               feature_config(true,
	                                                              "enable statsd",
	                                                              "statsd",
	                                                              "enabled")},
	{JMX,                  "jmx",                  feature_config(true,
	                                                              "enable jmx",
	                                                              "jmx",
	                                                              "enabled")},
	{APP_CHECKS,           "app checks",           feature_config(true,
	                                                              "enable app_checks",
	                                                              "app_checks_enabled")},
	{COINTERFACE,          "cointerface",          feature_config(true,
	                                                              "enable cointerface",
	                                                              "cointerface_enabled")},
	{DRIVER,               "driver",               feature_config(true,
	                                                              "enable driver. Note feature.full_syscalls",
	                                                              "feature",
	                                                              "driver")},
	{SECURE,               "secure",               feature_config(false,
	                                                              "enable secure",
	                                                              "security",
	                                                              "enabled")},
	{COMMAND_LINE_CAPTURE, "command line capture", feature_config(false,
	                                                              "enable command line capture",
	                                                              "commandlines_capture",
	                                                              "enabled")},
	{BASELINER,            "baseliner",            feature_config(false,
	                                                              "enable baseliner",
	                                                              "falcobaseline", 
	                                                              "enabled")},
	{MEMDUMP,              "memdump",              feature_config(false,
	                                                              "enable memdumper",
	                                                              "memdump",
	                                                              "enabled")},
	{SECURE_AUDIT,         "secure audit",         feature_config(false,
	                                                              "enable secure audit",
	                                                              "secure_audit_streams",
	                                                              "enabled")},
	{FULL_SYSCALLS,        "full syscalls",        feature_config(true,
	                                                              "enable collection of complete syscalls. Note feature.driver",
	                                                              "feature",
	                                                              "full_syscalls")},
	{NETWORK_BREAKDOWN,    "network breakdown",    feature_config(true,
                                                                  "enable collection of network stats by remote endpoint.",
                                                                  "feature",
                                                                  "network_breakdown")},
	{FILE_BREAKDOWN,       "file breakdown",       feature_config(true,
                                                                  "enable collection of file stats on a per-file basis",
                                                                  "feature",
                                                                  "file_breakdown")},
	{PROTOCOL_STATS,       "protocol stats",       feature_config(true,
                                                                  "enable collection of protocol stats",
                                                                  "feature",
                                                                  "protocol_stats")},
	{HTTP_STATS,           "http stats",           feature_config(true,
                                                                  "enable collection of http stats",
                                                                  "feature",
                                                                  "http_stats")},
	{MYSQL_STATS,          "mysql stats",          feature_config(true,
                                                                  "enable collection of mysql stats",
                                                                  "feature",
                                                                  "mysql_stats")},
	{POSTGRES_STATS,       "postgres stats",       feature_config(true,
                                                                  "enable collection of postgres stats",
                                                                  "feature",
                                                                  "postgres_stats")},
	{MONGODB_STATS,        "mongodb stats",        feature_config(true,
                                                                  "enable collection of mongodb stats",
                                                                  "feature",
                                                                  "mongodb_stats")},
	{MONITOR,              "monitor",              feature_config(true,
                                                                  "enable metrics",
                                                                  "feature",
                                                                  "monitor")},
	{NETWORK_TOPOLOGY,     "network topology",     feature_config(false,
	                                                              "enable network topology",
	                                                              "network_topology",
	                                                              "enabled")}
};
// clang-format on

static_assert(FEATURE_COUNT == sizeof(feature_manager::feature_configs) /
                                   sizeof(feature_manager::feature_configs[0]),
              "not all features have defined configs");

feature_config::feature_config(bool default_value,
                               const std::string& description,
                               const std::string& key,
                               const std::string& sub_key)
    : m_feature_enabled(default_value, description, key, sub_key),
      m_feature_force(false, "", key, sub_key + "_opt", "force"),
      m_feature_weak(false, "", key, sub_key + "_opt", "weak")
{
}

feature_config::feature_config(bool default_value,
                               const std::string& description,
                               const std::string& key)
    : m_feature_enabled(default_value, description, key),
      m_feature_force(false, "", key + "_opt", "force"),
      m_feature_weak(false, "", key + "_opt", "weak")
{
}
feature_manager& feature_manager::instance()
{
	if (s_instance == nullptr)
	{
		s_instance = new feature_manager();
	}

	return *s_instance;
}

feature_manager::feature_manager()
    : m_agent_variant(AGENT_VARIANT_TRADITIONAL),
      m_agent_mode(AGENT_MODE_NONE),
      m_feature_map(),
      m_custom_config(false)
{
	// NOTE: don't reference the two const maps here. I couldn't find a way for
	// them to actually get const initialized, so there's no guarantee they're
	// ready when we get here.
}

feature_manager::~feature_manager()
{
	// This is super ugly, but in test, the feature manager will leak values through configs,
	// which are global. So the best we can do is try to reset things once the
	// feature manager is destroyed
	auto config =
	    configuration_manager::instance().get_mutable_config<uint32_t>("http.url_table_size");
	config->set_set_in_config(false);
	config->set(1024);
}

static_assert(feature_manager::agent_variant::AGENT_VARIANT_TRADITIONAL ==
                  (feature_manager::agent_variant)draiosproto::agent_variant::variant_traditional,
              "agent variants must match");
static_assert(feature_manager::agent_variant::AGENT_VARIANT_AGENTONE ==
                  (feature_manager::agent_variant)draiosproto::agent_variant::variant_agentone,
              "agent variants must match");
static_assert(feature_manager::agent_variant::AGENT_VARIANT_AGENTINO ==
                  (feature_manager::agent_variant)draiosproto::agent_variant::variant_agentino,
              "agent variants must match");

static_assert(feature_manager::agent_mode::AGENT_MODE_MONITOR ==
                  (feature_manager::agent_mode)draiosproto::agent_mode::normal,
              "agent modes must match");
static_assert(feature_manager::agent_mode::AGENT_MODE_MONITOR_LIGHT ==
                  (feature_manager::agent_mode)draiosproto::agent_mode::light,
              "agent modes must match");
static_assert(feature_manager::agent_mode::AGENT_MODE_ESSENTIALS ==
                  (feature_manager::agent_mode)draiosproto::agent_mode::essentials,
              "agent modes must match");
static_assert(feature_manager::agent_mode::AGENT_MODE_TROUBLESHOOTING ==
                  (feature_manager::agent_mode)draiosproto::agent_mode::troubleshooting,
              "agent modes must match");
static_assert(feature_manager::agent_mode::AGENT_MODE_SECURE ==
                  (feature_manager::agent_mode)draiosproto::agent_mode::secure,
              "agent modes must match");

bool feature_manager::enable(feature_name feature, bool force)
{
	feature_base& input = *m_feature_map[feature];
	if (input.locked())
	{
		if (!input.get_enabled())
		{
			LOG_DEBUG("Attempt to enable feature %s, but was previously forced off",
			          feature_configs[feature].n.c_str());
			return false;
		}
		else
		{
			return true;
		}
	}

	input.set_enabled(true);
	input.set_locked();

	// just a naive BFS. check all dependencies are enabled/enableable, and lock
	// them as enabled. Return false if we reach a dependency which is locked disabled
	// or otherwise not enableable.
	std::list<feature_name> q;
	q.push_back(feature);
	while (!q.empty())
	{
		feature_base& on = *m_feature_map[q.front()];
		q.pop_front();
		for (feature_name dep : on.get_dependencies())
		{
			feature_base& next = *m_feature_map[dep];
			if (next.locked() && next.get_enabled())
			{
				// case 1: already processed. do nothing
			}
			else if (next.locked() && !next.get_enabled())
			{
				// case 2: already processed, but wrong. bail
				LOG_ERROR(
				    "Dependency %s of feature %s has been disabled either explicitly or as a "
				    "dependency of a different feature. Fix the configuration which is disabling "
				    "%s.",
				    feature_configs[next.m_name].n.c_str(),
				    feature_configs[on.m_name].n.c_str(),
				    feature_configs[next.m_name].n.c_str());
				return false;
			}
			else if (force || next.get_enabled() ||
			         (feature_configs[next.m_name].c.m_feature_enabled.get_value() &&
			          feature_configs[next.m_name].c.m_feature_enabled.is_set_in_config()))
			{
				// case 3: three sub-cases:
				// 1) we're forced, so we can do whatever
				// 2) we're already enabled by the profile, so there is no issue
				// 3) we have a config explicitly enabling this
				//
				// In all three cases, we can set it to enabled, and we must lock. Then recurse
				next.set_enabled(true);
				next.set_locked();
				LOG_DEBUG("Feature %s has ensured that %s is enabled",
				          feature_configs[on.m_name].n.c_str(),
				          feature_configs[next.m_name].n.c_str());
				q.push_back(next.m_name);
			}
			else
			{
				// case 4: can't enable. bail
				LOG_ERROR(
				    "Feature %s cannot enable dependency %s. Identify what is enabling this "
				    "(potentially dragent.auto.yaml)"
				    "feature, and disabling the dependency to resolve the conflict",
				    feature_configs[on.m_name].n.c_str(),
				    feature_configs[next.m_name].n.c_str());
				return false;
			}
		}
	}

	return true;
}

// Note the reason we didn't combine this with enable is because there are just too
// many small differences
// 1) many of the boolean directions are flipped
// 2) All the comments are different
// 3) the biggest, the direction of all the edges in the dependency tree are flipped
bool feature_manager::disable(feature_name feature, bool force)
{
	feature_base& input = *m_feature_map[feature];
	if (input.locked())
	{
		if (input.get_enabled())
		{
			LOG_DEBUG("Attempt to disable feature %s, but was previously forced on",
			          feature_configs[feature].n.c_str());
			return false;
		}
		else
		{
			return true;
		}
	}

	input.set_enabled(false);
	input.set_locked();

	// force disabled, so disable everything that depends on us.
	std::list<feature_name> q;
	q.push_back(feature);
	while (!q.empty())
	{
		feature_base& on = *m_feature_map[q.front()];
		q.pop_front();
		// We don't have the reverse mapping of dependencies, so
		// have to walk everything. n is small, so don't care
		// that this is n^2. If n becomes big, build reverse mapping in linear
		// time instead
		for (auto& j : m_feature_map)
		{
			for (auto& dep : j.second->get_dependencies())
			{
				if (dep == on.m_name)
				{
					feature_base& next = *m_feature_map[j.first];
					if (next.locked() && !next.get_enabled())
					{
						// case 1: already processed. do nothing
					}
					else if (next.locked() && next.get_enabled())
					{
						// case 2: already processed, but wrong. bail
						LOG_ERROR(
						    "Feature %s which depends on %s has been enabled either explicitly or "
						    "as a dependency of a different feature. Fix the configuration which "
						    "is enabling %s.",
						    feature_configs[next.m_name].n.c_str(),
						    feature_configs[on.m_name].n.c_str(),
						    feature_configs[next.m_name].n.c_str());
						return false;
					}
					else if (force || !next.get_enabled() ||
					         (!feature_configs[next.m_name].c.m_feature_enabled.get_value() &&
					          feature_configs[next.m_name].c.m_feature_enabled.is_set_in_config()))
					{
						// case 3: three sub-cases:
						// 1) we're forced, so we can do whatever
						// 2) we're already disabled by the profile, so there is no issue
						// 3) we have a config displicitly enabling this
						//
						// In all three cases, we can set it to disabled, and we must lock. Then
						// recurse
						next.set_enabled(false);
						next.set_locked();
						LOG_DEBUG("Feature %s has ensured that %s is disabled",
						          feature_configs[on.m_name].n.c_str(),
						          feature_configs[next.m_name].n.c_str());
						q.push_back(next.m_name);
					}
					else
					{
						// case 4: can't disable. bail
						LOG_ERROR(
						    "Feature %s depends on %s but cannot be disabled, as another feature "
						    "depends on it. Identify what is enabling "
						    "this dependency"
						    "(potentially dragent.auto.yaml),"
						    "and disabling this feature to resolve the conflict",
						    feature_configs[next.m_name].n.c_str(),
						    feature_configs[on.m_name].n.c_str());
						return false;
					}
				}
			}
		}
	}

	return true;
}

bool feature_manager::try_enable(feature_name feature)
{
	feature_base& input = *m_feature_map[feature];
	if (input.locked())
	{
		return input.get_enabled();
	}

	// We BFS to validate that it will work, then commit
	std::list<feature_name> q;
	q.push_back(feature);
	std::set<feature_name> visited;
	visited.insert(feature);
	while (!q.empty())
	{
		feature_base& on = *m_feature_map[q.front()];
		q.pop_front();
		for (feature_name dep : on.get_dependencies())
		{
			if (visited.find(dep) == visited.end())
			{
				feature_base& next = *m_feature_map[dep];
				if (next.locked() && next.get_enabled())
				{
					// case 1: nothing to do
				}
				else if (next.locked() && !next.get_enabled())
				{
					// case 2: disabled and can't enable. bail
					return false;
				}
				else if (next.get_enabled() ||
				         (feature_configs[next.m_name].c.m_feature_enabled.get_value() &&
				          feature_configs[next.m_name].c.m_feature_enabled.is_set_in_config()))
				{
					// two subcases:
					// 1) already enabled
					// 2) can be enabled by config
					q.push_back(next.m_name);
				}
				else
				{
					// case 4: disabled and can't enable
					return false;
				}
			}
		}
	}

	bool success = enable(feature, false);
	if (!success)
	{
		assert(false);  // This should never fail given we just validated it will succeed...
	}

	return success;
}

// Note the reason we didn't combine this with enable is because there are just too
// many small differences
// 1) many of the boolean directions are flipped
// 2) All the comments are different
// 3) the biggest, the direction of all the edges in the dependency tree are flipped
bool feature_manager::try_disable(feature_name feature)
{
	feature_base& input = *m_feature_map[feature];
	if (input.locked())
	{
		return !input.get_enabled();
	}

	// BFS first, then commit
	std::list<feature_name> q;
	q.push_back(feature);
	std::set<feature_name> visited;
	visited.insert(feature);
	while (!q.empty())
	{
		feature_base& on = *m_feature_map[q.front()];
		q.pop_front();

		for (auto& j : m_feature_map)
		{
			for (auto& dep : j.second->get_dependencies())
			{
				if (dep == on.m_name)
				{
					if (visited.find(j.first) == visited.end())
					{
						feature_base& next = *m_feature_map[j.first];
						if (next.locked() && !next.get_enabled())
						{
							// case 1: nothing to do
						}
						else if (next.locked() && next.get_enabled())
						{
							// case 2: enabled and can't disable. bail
							return false;
						}
						else if (!next.get_enabled() ||
						         (!feature_configs[next.m_name].c.m_feature_enabled.get_value() &&
						          feature_configs[next.m_name]
						              .c.m_feature_enabled.is_set_in_config()))
						{
							// two subcases:
							// 1) already disabled
							// 2) can be disabled by config
							q.push_back(next.m_name);
						}
						else
						{
							// case 4: enabled and can't disable
							return false;
						}
					}
				}
			}
		}
	}

	bool success = disable(feature, false);
	if (!success)
	{
		assert(false);  // This should never fail given we just validated it will succeed...
	}

	return success;
}

bool feature_manager::verify_dependencies()
{
	// Walk through all the enabled features and ensure their dependencies are enabled
	for (auto& i : m_feature_map)
	{
		LOG_DEBUG("\tFeature %s is %s %s",
		          feature_configs[i.first].n.c_str(),
		          i.second->locked() ? "" : "tentatively",
		          i.second->get_enabled() ? "enabled" : "disabled");
		if (i.second->get_enabled())
		{
			if (!i.second->verify_dependencies())
			{
				LOG_ERROR("Dependency verification for feature %s failed",
				          feature_configs[i.first].n.c_str());
				return false;
			}
		}
	}

	return true;
}

bool feature_manager::initialize(agent_variant variant)
{
	for (const agent_mode_container& mode : mode_definitions)
	{
		if (c_agent_mode.get_value() == mode.m_name)
		{
			return initialize(variant, mode.m_mode);
		}
	}

	// for backwards compatibility with "how we used to do things," if
	// a un-found mode is found, we initialize in legacy mode
	return initialize(variant, AGENT_MODE_NONE);
}

bool feature_manager::initialize(agent_variant variant, agent_mode mode)
{
#ifdef _DEBUG
	for (uint32_t i = 0; i < AGENT_VARIANT_COUNT; i++)
	{
		assert(variant_definitions[i].m_variant == (agent_variant)i);
	}
	for (uint32_t i = 0; i < AGENT_MODE_COUNT; i++)
	{
		assert(mode_definitions[i].m_mode == (agent_mode)i);
	}
	for (uint32_t i = 0; i < FEATURE_COUNT; i++)
	{
		assert(feature_configs[i].f == (feature_name)i);
	}
#endif

	m_agent_variant = variant;
	m_agent_mode = mode;

	LOG_INFO("Initializing Agent in %s variant and %s mode",
	         variant_definitions[m_agent_variant].m_name.c_str(),
	         mode_definitions[m_agent_mode].m_name.c_str());

	if (m_agent_mode == AGENT_MODE_NONE)
	{
		// If mode is none, take the values from the regular configs
		for (auto& i : feature_configs)
		{
			m_feature_map[i.f]->set_enabled(i.c.m_feature_enabled.get_value());
		}
	}
	else
	{
		// Pass 1: enable features as they are defined in the feature table
		for (auto& i : m_feature_map)
		{
			i.second->set_unlocked();  // only really necessary for tests, which might reinit
			i.second->set_enabled(false);
		}
		LOG_DEBUG("Setting default features for mode");
		for (const auto& i : mode_definitions[m_agent_mode].m_enabled_features)
		{
			LOG_DEBUG("Tentatively Enabling %s", feature_configs[i].n.c_str());
			m_feature_map[i]->set_enabled(true);
		}

		if (!verify_dependencies())
		{
			return false;
		}

		// Pass 2: look for "force" features explicitly specified in the config.
		// Set them and their dependencies appropriately
		LOG_DEBUG("Setting forced features. All necessary dependencies will be enabled or disabled as appropriate.");
		for (auto& i : m_feature_map)
		{
			const auto& config = feature_configs[i.first].c;
			if (config.m_feature_enabled.is_set_in_config() && config.m_feature_force.get_value())
			{
				LOG_DEBUG("%s %s and all necessary dependencies",
				          config.m_feature_enabled.get_value() ? "Enabling" : "Disabling",
				          feature_configs[i.first].n.c_str());
				if (!(config.m_feature_enabled.get_value() ? enable(i.first, true)
				                                           : disable(i.first, true)))
				{
					return false;
				}
			}
		}

		if (!verify_dependencies())
		{
			return false;
		}

		// Pass 3: look for "regular" features specified in the config. Set them.
		LOG_DEBUG("Setting configured features. Operation will fail if dependencies are not met");
		for (auto& i : m_feature_map)
		{
			const auto& config = feature_configs[i.first].c;
			if (config.m_feature_enabled.is_set_in_config() &&
			    !config.m_feature_force.get_value() && !config.m_feature_weak.get_value())
			{
				LOG_DEBUG("%s %s",
				          config.m_feature_enabled.get_value() ? "Enabling" : "Disabling",
				          feature_configs[i.first].n.c_str());
				if (!(config.m_feature_enabled.get_value() ? enable(i.first, false)
				                                           : disable(i.first, false)))
				{
					return false;
				}
			}
		}

		if (!verify_dependencies())
		{
			return false;
		}

		// Pass 4: look for "weak" features specified in the config. Set them only
		// if able
		LOG_DEBUG("Setting weakly configured features. Feature only set IF dependencies are met");
		for (auto& i : m_feature_map)
		{
			const auto& config = feature_configs[i.first].c;
			if (config.m_feature_enabled.is_set_in_config() &&
			    !config.m_feature_force.get_value() && config.m_feature_weak.get_value())
			{
				LOG_DEBUG("Conditionally %s %s",
				          config.m_feature_enabled.get_value() ? "enabling" : "disabling",
				          feature_configs[i.first].n.c_str());
				if (config.m_feature_enabled.get_value())
				{
					try_enable(i.first);
				}
				else
				{
					try_disable(i.first);
				}
			}
		}

		if (!verify_dependencies())
		{
			return false;
		}
	}

	// Enable any one-off configs
	LOG_DEBUG("Enforcing one-off configuration settings for specified mode");
	for (const auto& i : mode_definitions[m_agent_mode].m_extra_configs)
	{
		bool rc = i.second->enforce(i.first);
		if (!rc)
		{
			LOG_INFO(
			    "Unable to enforce config %s as it is explicitly overridden in the configuration. "
			    "Custom-configuration will be indicated.",
			    i.first.c_str());
			m_custom_config = true;
		}
		else
		{
			LOG_INFO("Config %s updated by feature manager", i.first.c_str());
		}
	}

	// Give the features some opportunity to do some init work if they so choose
	// before later startup. This may involve disabling themselves in certain circumstances.
	for (auto& i : m_feature_map)
	{
		if (i.second->get_enabled())
		{
			if (!i.second->initialize())
			{
				LOG_ERROR("Initialization failed for feature %s",
				          feature_configs[i.first].n.c_str());
				return false;
			}
		}
	}

	LOG_INFO("Feature manager initialization completed");
	for (const auto& i : m_feature_map)
	{
		LOG_INFO("\t%s: %s",
		         feature_configs[i.first].n.c_str(),
		         i.second->get_enabled() ? "Enabled" : "Disabled");
	}

	return true;
}

void feature_manager::to_protobuf(draiosproto::feature_status& feature_pb) const
{
	feature_pb.set_variant((draiosproto::agent_variant)m_agent_variant);
	feature_pb.set_mode((draiosproto::agent_mode)m_agent_mode);
	for (const auto& feature : m_feature_map)
	{
		feature.second->emit_enabled(feature_pb);
	}
	feature_pb.set_custom_config(m_custom_config);
}

void feature_manager::register_feature(feature_name name, feature_base& feature)
{
	auto preexisting_feature = m_feature_map.find(name);

	assert(preexisting_feature == m_feature_map.end());
	if (preexisting_feature != m_feature_map.end())
	{
		// note can't log string here as table is not guaranteed to be initialized yet
		LOG_ERROR("Feature %d already exists, skipping", name);
		return;
	}

	m_feature_map.insert(std::pair<feature_name, feature_base*>(name, &feature));
}

bool feature_manager::get_enabled(feature_name name) const
{
	return m_feature_map.find(name)->second->get_enabled();
}

bool feature_manager::deprecated_disable(feature_name name)
{
	for (auto& i : m_feature_map)
	{
		if (i.second->get_enabled() && std::find(i.second->get_dependencies().begin(),
		                                         i.second->get_dependencies().end(),
		                                         name) != i.second->get_dependencies().end())
		{
			LOG_ERROR("Failed to disable feature %s as %s depends on it",
			          feature_configs[name].n.c_str(),
			          feature_configs[i.first].n.c_str());
			return false;
		}
	}

	m_feature_map[name]->set_enabled(false);
	return true;
}

feature_base::feature_base(feature_name feature,
                           void (draiosproto::feature_status::*pb_extractor)(bool),
                           const std::list<feature_name>& dependencies)
    : m_name(feature),
      m_enabled(false),
      m_locked(false),
      m_pb_extractor(pb_extractor),
      m_dependencies(dependencies),
      m_manager(feature_manager::instance())
{
	m_manager.register_feature(feature, *this);
}

feature_base::feature_base(feature_name feature,
                           void (draiosproto::feature_status::*pb_extractor)(bool),
                           const std::list<feature_name>& dependencies,
                           feature_manager& manager)
    : m_name(feature),
      m_enabled(false),
      m_locked(false),
      m_pb_extractor(pb_extractor),
      m_dependencies(dependencies),
      m_manager(manager)
{
	manager.register_feature(feature, *this);
}

bool feature_base::get_enabled() const
{
	return m_enabled;
}

void feature_base::set_enabled(bool value)
{
	assert(!locked());
	m_enabled = value;
}

void feature_base::set_locked()
{
	assert(!locked());
	m_locked = true;
}

void feature_base::set_unlocked()
{
	m_locked = false;
}

bool feature_base::locked() const
{
	return m_locked;
}

bool feature_base::verify_dependencies() const
{
	for (auto& j : get_dependencies())
	{
		if (!m_manager.get_enabled(j))
		{
			LOG_ERROR("Dependency validation for feature %s failed. Requires %s to be enabled",
			          feature_manager::feature_configs[m_name].n.c_str(),
			          feature_manager::feature_configs[j].n.c_str());
			return false;
		}
	}

	return true;
}

const std::list<feature_name>& feature_base::get_dependencies() const
{
	return m_dependencies;
}

bool feature_base::initialize()
{
	return true;
}

void feature_base::emit_enabled(draiosproto::feature_status& feature_pb) const
{
	(feature_pb.*m_pb_extractor)(get_enabled());
}

namespace
{
// Prometheus has a prometheus_conf which kind of serves this purpose, but
// we maintain multiple copies of it, and depend on the enablement of its contained (really
// derived) filter. Straightening that out will be a bit of a chore, so for now, we maintain
// the state separately and trust that nobody is YOLO enabling prom if its disabled in
// config
//
// After feature manager is initialized, dragent will ensure prometheus' view of the world
// is aligned with ours
feature_base prometheus_feature(PROMETHEUS,
                                &draiosproto::feature_status::set_prometheus_enabled,
                                {});
feature_base jmx_feature(JMX, &draiosproto::feature_status::set_jmx_enabled, {});
feature_base app_checks_feature(APP_CHECKS,
                                &draiosproto::feature_status::set_app_checks_enabled,
                                {});
feature_base cointerface_feature(COINTERFACE,
                                 &draiosproto::feature_status::set_cointerface_enabled,
                                 {});
feature_base monitor_feature(MONITOR, &draiosproto::feature_status::set_monitor_enabled, {});
feature_base driver_feature(DRIVER, &draiosproto::feature_status::set_driver_enabled, {});

feature_base full_syscalls_feature(FULL_SYSCALLS,
                                   &draiosproto::feature_status::set_full_syscalls_enabled,
                                   {DRIVER});
feature_base baseliner_feature(BASELINER,
                               &draiosproto::feature_status::set_baseliner_enabled,
                               {DRIVER, FULL_SYSCALLS});
feature_base memdump_feature(MEMDUMP, &draiosproto::feature_status::set_memdump_enabled, {});
feature_base secure_audit_feature(SECURE_AUDIT,
                                  &draiosproto::feature_status::set_secure_audit_enabled,
                                  {SECURE});

feature_base network_topology_feature(NETWORK_TOPOLOGY,
                                      &draiosproto::feature_status::set_network_topology_enabled,
                                      {SECURE});

feature_base network_breakdown_feature(NETWORK_BREAKDOWN,
                                       &draiosproto::feature_status::set_network_breakdown_enabled,
                                       {FULL_SYSCALLS});
feature_base file_breakdown_feature(FILE_BREAKDOWN,
                                    &draiosproto::feature_status::set_file_breakdown_enabled,
                                    {FULL_SYSCALLS});

/**
 * command line has a weird dependency where it gets disabled if secure audit
 * is enabled. We do this at initialization time.
 */
class commandline_capture_feature_class : public feature_base
{
public:
	commandline_capture_feature_class()
	    : feature_base(COMMAND_LINE_CAPTURE,
	                   &draiosproto::feature_status::set_commandline_capture_enabled,
	                   {})
	{
	}

	bool initialize() override
	{
		// There is a gap here, where if secure audit were to try to disable itself,
		// we would be a bit of a race. Secure audit doesn't do this, though.
		//
		// It would be nice if we had a cleaner way to do this.
		if (feature_manager::instance().get_enabled(SECURE_AUDIT))
		{
			return feature_manager::instance().deprecated_disable(COMMAND_LINE_CAPTURE);
		}

		return true;
	}
};
commandline_capture_feature_class commandline_capture_feature;

}  // namespace
