#include "common.pb.h"
#include "common_logger.h"
#include "configuration_manager.h"
#include "feature_manager.h"
namespace
{
feature_manager* s_instance = nullptr;

type_config<std::string> c_agent_mode("none", "the agent mode to execute in.", "feature", "mode");

}  // namespace

const feature_manager::agent_mode_container feature_manager::mode_definitions[] = {
    {feature_manager::AGENT_MODE_NONE, "none", {}},
    {feature_manager::AGENT_MODE_MONITOR,
     "monitor",
     {STATSD, JMX, APP_CHECKS, COINTERFACE, DRIVER, FULL_SYSCALLS}},
    {feature_manager::AGENT_MODE_MONITOR_LIGHT, "monitor_light", {}}};

static_assert(feature_manager::agent_mode::AGENT_MODE_COUNT ==
                  sizeof(feature_manager::mode_definitions) /
                      sizeof(feature_manager::mode_definitions[0]),
              "not all agent modes definined");

// clang-format off
const feature_manager::agent_feature_container feature_manager::feature_configs[] =
{
	{PROMETHEUS,           "prometheus",           type_config<bool>(false,
	                                                                 "enable prom",
	                                                                 "prometheus",
	                                                                 "enabled")},
	{STATSD,               "statsd",               type_config<bool>(true,
	                                                                 "enable statsd",
	                                                                 "statsd",
	                                                                 "enabled")},
	{JMX,                  "jmx",                  type_config<bool>(true,
	                                                                 "enable jmx",
	                                                                 "jmx",
	                                                                 "enabled")},
	{APP_CHECKS,           "app checks",           type_config<bool>(true,
	                                                                 "enable app_checks",
	                                                                 "app_checks_enabled")},
	{COINTERFACE,          "cointerface",          type_config<bool>(true,
	                                                                 "enable cointerface",
	                                                                 "cointerface_enabled")},
	{DRIVER,               "driver",               type_config<bool>(true,
	                                                                 "enable driver. Note feature.full_syscalls",
	                                                                 "feature",
	                                                                 "driver")},
	{SECURE,               "secure",               type_config<bool>(false,
	                                                                 "enable secure",
	                                                                 "security",
	                                                                 "enabled")},
	{COMMAND_LINE_CAPTURE, "command line capture", type_config<bool>(false,
	                                                                 "enable command line capture",
	                                                                 "commandlines_capture",
	                                                                 "enabled")},
	{BASELINER,            "baseliner",            type_config<bool>(false,
	                                                                 "enable baseliner",
	                                                                 "falcobaseline", 
	                                                                 "enabled")},
	{MEMDUMP,              "memdump",              type_config<bool>(false,
	                                                                 "enable memdumper",
	                                                                 "memdump",
	                                                                 "enabled")},
	{SECURE_AUDIT,         "secure audit",         type_config<bool>(false,
	                                                                 "enable secure audit",
	                                                                 "secure_audit_streams",
	                                                                 "enabled")},
	{FULL_SYSCALLS,        "full syscalls",        type_config<bool>(true,
	                                                                 "enable collection of complete syscalls. Note feature.driver",
	                                                                 "feature",
	                                                                 "full_syscalls")}
};
// clang-format on

static_assert(FEATURE_COUNT == sizeof(feature_manager::feature_configs) /
                                   sizeof(feature_manager::feature_configs[0]),
              "not all features have defined configs");

feature_manager& feature_manager::instance()
{
	if (s_instance == nullptr)
	{
		s_instance = new feature_manager();
	}

	return *s_instance;
}

feature_manager::feature_manager() : m_agent_mode(AGENT_MODE_NONE), m_feature_map()
{
	// NOTE: don't reference the two const maps here. I couldn't find a way for
	// them to actually get const initialized, so there's no guarantee they're
	// ready when we get here.
}

static_assert(feature_manager::agent_mode::AGENT_MODE_MONITOR ==
                  (feature_manager::agent_mode)draiosproto::agent_mode::normal,
              "agent modes must match");
static_assert(feature_manager::agent_mode::AGENT_MODE_MONITOR_LIGHT ==
                  (feature_manager::agent_mode)draiosproto::agent_mode::light,
              "agent modes must match");

bool feature_manager::initialize()
{
#ifdef _DEBUG
	for (uint32_t i = 0; i < AGENT_MODE_COUNT; i++)
	{
		assert(mode_definitions[i].m_mode == (agent_mode)i);
	}
	for (uint32_t i = 0; i < FEATURE_COUNT; i++)
	{
		assert(feature_configs[i].f == (feature_name)i);
	}
#endif

	for (const agent_mode_container& mode : mode_definitions)
	{
		if (c_agent_mode.get_value() == mode.m_name)
		{
			m_agent_mode = mode.m_mode;
			break;
		}
	}

	// g_log->information("Agent set in " + mode_definitions[m_agent_mode].m_name + " mode");

	if (m_agent_mode == AGENT_MODE_NONE)
	{
		// If mode is none, take the values from the regular configs
		for (auto& i : feature_configs)
		{
			m_feature_map.find(i.f)->second.set_enabled(i.c.get_value());
		}
	}
	else
	{
		// If mode is NOT none, use the configs as provided by the mode definition.
		// In future versions, you'll be able to do both.
		for (auto& i : m_feature_map)
		{
			i.second.set_enabled(false);
		}
		for (const auto& i : mode_definitions[m_agent_mode].m_enabled_features)
		{
			m_feature_map.find(i)->second.set_enabled(true);
		}
	}

	// Walk through all the enabled features and ensure their dependencies are enabled
	for (auto& i : m_feature_map)
	{
		// g_log->information("Feature " + feature_configs[i.first].n + " is tentatively " +
		//                  (i.second.get_enabled() ? "enabled" : "disabled"));
		if (i.second.get_enabled())
		{
			if (!i.second.verify_dependencies())
			{
				return false;
			}
		}
	}

	// Give the features some opportunity to do some init work if they so choose
	// before later startup. This may involve disabling themselves in certain circumstances.
	for (auto& i : m_feature_map)
	{
		if (i.second.get_enabled())
		{
			if (!i.second.initialize())
			{
				// g_log->error("Initialization failed for feature " + feature_configs[i.first].n);
				return false;
			}
		}
	}

	return true;
}

void feature_manager::to_protobuf(draiosproto::feature_status& feature_pb) const
{
	feature_pb.set_mode((draiosproto::agent_mode)m_agent_mode);
	for (const auto feature : m_feature_map)
	{
		feature.second.emit_enabled(feature_pb);
	}
}

void feature_manager::register_feature(feature_name name, feature_base& feature)
{
	auto preexisting_feature = m_feature_map.find(name);

	assert(preexisting_feature == m_feature_map.end());
	if (preexisting_feature != m_feature_map.end())
	{
		// g_log->error("Feature " + feature_configs[name].n + " already exists, skipping.");
		return;
	}

	m_feature_map.insert(std::pair<feature_name, feature_base&>(name, feature));
}

bool feature_manager::get_enabled(feature_name name) const
{
	return m_feature_map.find(name)->second.get_enabled();
}

bool feature_manager::disable(feature_name name)
{
	for (auto& i : m_feature_map)
	{
		if (i.second.get_enabled() && std::find(i.second.get_dependencies().begin(),
		                                        i.second.get_dependencies().end(),
		                                        name) != i.second.get_dependencies().end())
		{
			// g_log->error("Failed to disable feature " + feature_configs[name].n + " as " +
			//            feature_configs[i.first].n + " depends on it");
			return false;
		}
	}

	m_feature_map.find(name)->second.set_enabled(false);
	return true;
}

feature_base::feature_base(feature_name feature,
                           void (draiosproto::feature_status::*pb_extractor)(bool),
                           const std::list<feature_name>& dependencies)
    : m_name(feature),
      m_enabled(false),
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
	m_enabled = value;
}

bool feature_base::verify_dependencies() const
{
	for (auto& j : get_dependencies())
	{
		if (!m_manager.get_enabled(j))
		{
			// g_log->error("Dependency validation for feature " + feature_configs[m_name].n + "
			// failed. Requires " + feature_configs[j].n + " to be enabled");
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
// derived) filter. Straightening that out will be a bit of a chore, so for now, we maintain the
// state separately and trust that nobody is YOLO enabling prom if its disabled in config
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
			return feature_manager::instance().disable(COMMAND_LINE_CAPTURE);
		}

		return true;
	}
};
commandline_capture_feature_class commandline_capture_feature;

}  // namespace
