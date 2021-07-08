#pragma once
#include "type_config.h"
#include "configuration_manager.h"

#include <functional>
#include <list>
#include <map>
#include <set>

/**
 * The feature manager serves as a general manager for modules/features in the system. It
 * currently mostly manages the dependencies between features and thus ensures the features
 * which are enabled result in a valid configuration.
 *
 * The feature_manager is the center point for this, and is a global instance. As the agent
 * is coming online, after configs are parsed, we invoke "initialize" which will verify the
 * configuration, provide features a "last chance" to disable themselves, and then return
 * a good or bad status.
 *
 * During runtime, the feature_manager largely just is a central place to check what
 * features are enabled, using the get_enabled api.
 *
 * Lastly, it manages dumping the features protobuf message when requested.
 *
 * Each feature implements one of the 'feature_name's and inherits from feature base.
 * We expect each entry in feature name to be represented by exactly 1 feature_base, which
 * registers itself with the feature_manager at creation. We expect these instances
 * to be created (and thus registered) by the time the feature_manager is initialized, and
 * largely, this means they will be static initializations.
 *
 * While we intend that each feature will have a module which inherits the feature base,
 * at time of writing, this is untenable. As such, "courtesy" implementations exist
 * which provide the missing feature definitions. We expect these courtesy_features to disappear
 * over time.
 *
 * The feature manager defines a set of modes which can be enabled. These each
 * comprise a set of features which are turned on by default. At present, it is unsupported
 * to set an agent mode as well as one of the feature modes. Therefore we expect
 * none of the features to be set directly OR agent mode to be "invalid." In the future,
 * this will likely be more graceful. If this assumption is broken, the definition of
 * the mode will override any explicitly set configs.
 */
namespace draiosproto
{
class feature_status;
}

enum feature_name
{
	PROMETHEUS,
	STATSD,
	JMX,
	APP_CHECKS,
	COINTERFACE,
	DRIVER,
	SECURE,
	COMMAND_LINE_CAPTURE,
	BASELINER,
	MEMDUMP,
	SECURE_AUDIT,
	FULL_SYSCALLS,
	NETWORK_BREAKDOWN,
	FILE_BREAKDOWN,
	PROTOCOL_STATS,
	HTTP_STATS,
	MYSQL_STATS,
	POSTGRES_STATS,
	MONGODB_STATS,
	MONITOR,
	NETWORK_TOPOLOGY,

	FEATURE_COUNT
};

class feature_config
{
public:
	feature_config(bool default_value,
	               const std::string& description,
	               const std::string& key,
	               const std::string& sub_key);

	feature_config(bool default_value, const std::string& description, const std::string& key);

	// whether the config says to enable a feature,
	type_config<bool> m_feature_enabled;
	// if this feature is explicitly enabled, enable all its dependencies, unless
	// explicitly disabled, in which case, bail
	type_config<bool> m_feature_force;
	// disable this feature if one of its dependencies is disabled, unless explicitly
	// enabled, in which case, bail
	type_config<bool> m_feature_weak;
};

class feature_manager;

/**
 * API for classes which want to serve as features owned by the feature manager
 */
class feature_base
{
public:
	/**
	 * ctor
	 *
	 * @param feature: the name of the feature this feature_base represents
	 * @param pb_extractor: function that we use to populate the protobuf when emitting the feature
	 * state
	 * @param dependencies: list of dependencies this feature has. Agent will not start if not all
	 * required dependencies are met
	 *
	 * Automagically registers with the feature_manager
	 */
	feature_base(feature_name feature,
	             void (draiosproto::feature_status::*pb_extractor)(bool),
	             const std::list<feature_name>& dependencies);

	/**
	 * a constructor on the off-chance that you want to register with
	 * a different manager. Likely only useful for test
	 */
	feature_base(feature_name feature,
	             void (draiosproto::feature_status::*pb_extractor)(bool),
	             const std::list<feature_name>& dependencies,
	             feature_manager& manager);

	/**
	 * return true if this feature is enabled
	 */
	virtual bool get_enabled() const;

	/**
	 * update whether this feature is enabled. USE WITH CAUTION! Should generally only
	 * be used by the feature_manager during initialization. And certainly never after.
	 */
	virtual void set_enabled(bool value);

	/**
	 * Invoke the function provided at construction time to dump the feature's status
	 * to the input pb
	 */
	void emit_enabled(draiosproto::feature_status& feature_pb) const;

	/**
	 * validates that this feature's dependencies are met by the current state of the
	 * feature manager
	 */
	virtual bool verify_dependencies() const;

	/**
	 * invoked after dependencies are verfied for whatever work the feature wants to do.
	 * Features may still disable themselves in this call WITH THE CAVEAT that there is
	 * no guaranteed ordering among calls to various features initializations (other than
	 * the calls are single threaded). Calls to disable are verified against the current
	 * set of enabled features.
	 */
	virtual bool initialize();

	/**
	 * get the list of dependencies on which this feature depends
	 */
	const std::list<feature_name>& get_dependencies() const;

	/**
	 * indicates that the value of this config ought not be changed again
	 */
	void set_locked();
	void set_unlocked();  // should really only ever be used in test code
	bool locked() const;

	const feature_name m_name;

private:
	bool m_enabled;
	bool m_locked;  // When a feature is "locked" its value can not be changed. If something
	                // tries to change it, the config is invalid and will be rejected
	void (draiosproto::feature_status::*m_pb_extractor)(bool);
	const std::list<feature_name> m_dependencies;
	feature_manager& m_manager;
};

/**
 * the two following classes, config_placeholder, and config_placeholder_impl
 * serve as the container that allows us to statically track type_configs that need
 * to be enabled alongside each mode.
 */
class config_placeholder
{
public:
	virtual bool enforce(std::string key) const = 0;
};

template<typename data_type>
class config_placeholder_impl : public config_placeholder
{
public:
	config_placeholder_impl(const data_type& value) : config_placeholder(), m_value(value) {}
	const data_type m_value;

	static config_placeholder_impl* build(data_type value)
	{
		return new config_placeholder_impl<data_type>(value);
	}

	bool enforce(std::string key) const override
	{
		type_config<data_type>* config =
		    configuration_manager::instance().get_mutable_config<data_type>(key);

		if (config == nullptr)
		{
			assert(false);
			return false;
		}

		if (config->get_value() == m_value)
		{
			return true;
		}
		else
		{
			if (!config->is_set_in_config())
			{
				config->set(m_value);
				return true;
			}
			else
			{
				return false;
			}
		}
	}
};

/**
 * manages configuration and enablement of all feature modules in the agent
 */
class feature_manager
{
public:
	enum agent_variant
	{
		AGENT_VARIANT_TRADITIONAL = 0,
		AGENT_VARIANT_AGENTONE = 1,
		AGENT_VARIANT_AGENTINO = 2,

		AGENT_VARIANT_COUNT
	};

	/**
	 * structure for encoding the definitions of the feature variants.
	 */
	struct agent_variant_container
	{
		/**
		 * the enum value of this variant
		 */
		const feature_manager::agent_variant m_variant;

		/**
		 * the string value for display
		 */
		const std::string m_name;
	};

	static const agent_variant_container variant_definitions[];


	enum agent_mode
	{
		AGENT_MODE_NONE = 0,
		AGENT_MODE_MONITOR = 1,
		AGENT_MODE_MONITOR_LIGHT = 2,
		AGENT_MODE_ESSENTIALS = 3,
		AGENT_MODE_TROUBLESHOOTING = 4,
		AGENT_MODE_SECURE = 5,
		AGENT_MODE_AGENTINO = 6,
		AGENT_MODE_AGENTONE = 7,

		AGENT_MODE_COUNT
	};

	/**
	 * structure for encoding the definitions of the feature modes.
	 */
	struct agent_mode_container
	{
		/**
		 * the enum value of this mode
		 */
		const feature_manager::agent_mode m_mode;

		/**
		 * the string value as to be expected from the yaml config
		 */
		const std::string m_name;

		/**
		 * the set of features to be enabled by default with this mode
		 */
		const std::set<feature_name> m_enabled_features;

		/**
		 * some additional configs may need to be set. We store them here
		 */
		const std::unordered_map<std::string, config_placeholder*> m_extra_configs;
	};

	static const agent_mode_container mode_definitions[];

	struct agent_feature_container
	{
		const feature_name f;
		const std::string n;
		const feature_config c;
	};

	static const agent_feature_container feature_configs[];

	feature_manager();
	~feature_manager();

	/**
	 * invoke to emit the current feature-state to the input protobuf.
	 */
	void to_protobuf(draiosproto::feature_status& feature_pb) const;

	/**
	 * register a feature with the feature manager. It is expected that every
	 * feature is registered exactly once, and that this registration occurs before
	 * initialization
	 */
	void register_feature(feature_name name, feature_base& feature);

	/**
	 * returns whether the input feature is enabled
	 */
	bool get_enabled(feature_name name) const;

	/**
	 * disable the named feature. May fail if some other enabled feature depends on this
	 * or if the feature itself does not want to be disabled (for instance, if it is
	 * already running and doesn't support not running without a restart)
	 *
	 * considered deprecated as this will not be long term supported behavior when
	 * profiles support disabled dependencies (instead of just enabled)
	 */
	bool deprecated_disable(feature_name name);

	/**
	 * get the global instance of the feature_manager
	 */
	static feature_manager& instance();

	/**
	 * initialize the feature manager. This will largely ensure that each
	 * feature has the proper "enabled" value from the registered configs as
	 * well as validate the enabled featureset is valid. In the future, this
	 * may also manage the actual initialization of the features.
	 *
	 * There are two apis that function equivalently, but one allows the specification
	 * of the mode to use, while the other uses the configured default
	 */
	bool initialize(agent_variant variant);
	bool initialize(agent_variant variant, agent_mode mode);

private:
	bool enable(feature_name feature, bool force);
	bool disable(feature_name feature, bool force);
	bool try_enable(feature_name feature);
	bool try_disable(feature_name feature);
	bool verify_dependencies();

	agent_variant m_agent_variant;
	agent_mode m_agent_mode;
	std::map<feature_name, feature_base*> m_feature_map;

	/**
	 * this indicates whether a config has been modified from the mode's
	 * standard configuration. This is sent to the backend, and may impact pricing.
	 */
	bool m_custom_config;

	friend class test_helper;
};
