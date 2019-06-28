/**
 * @file
 *
 * Implementation of fault_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#if defined(FAULT_INJECTION_ENABLED)

#include "fault_handler.h"
#include "fault_handler_registry.h"

#include <chrono>
#include <functional>
#include <fstream>
#include <random>
#include <sstream>
#include <json/json.h>

namespace
{

const std::string ALWAYS = "ALWAYS";
const std::string ONE_SHOT = "ONE_SHOT";
const std::string PROBABILITY = "PROBABILITY";
const std::string AFTER_N = "AFTER_N";

static std::default_random_engine s_rand_generator(
		std::chrono::system_clock::now().time_since_epoch().count());

/**
 * Return a random number between [1, 100]
 */
uint8_t next_rand()
{
	static std::uniform_int_distribution<uint8_t> rand_distribution(1, 100);

	return rand_distribution(s_rand_generator);
}

/**
 * The concrete realization of the memento interface.  Saves the state of
 * a fault_handler.
 */
class concrete_memento : public userspace_shared::fault_handler::memento
{
public:
	concrete_memento(const std::string& name,
	                 const uint64_t fault_uint64,
	                 const std::string& fault_string,
	                 const uint32_t fired_count,
	                 const uint32_t hit_count,
	                 const uint16_t n_count,
	                 const userspace_shared::fault_handler::fault_mode fault_mode,
	                 const bool enabled,
	                 const uint8_t probability):
		m_name(name),
		m_fault_uint64(fault_uint64),
		m_fault_string(fault_string),
		m_fired_count(fired_count),
		m_hit_count(hit_count),
		m_n_count(n_count),
		m_fault_mode(fault_mode),
		m_enabled(enabled),
		m_probability(probability)
	{ }

	const std::string m_name;
	uint64_t m_fault_uint64;
	std::string m_fault_string;
	uint32_t m_fired_count;
	uint32_t m_hit_count;
	uint16_t m_n_count;
	userspace_shared::fault_handler::fault_mode m_fault_mode;
	bool m_enabled;
	uint8_t m_probability;
};

} // end namespace


namespace userspace_shared
{

fault_handler::fault_handler(const std::string& filename,
                             const uint16_t line,
                             const std::string& name,
                             const std::string& description):
	m_fault_uint64(0),
	m_filename(filename),
	m_name(name),
	m_description(description),
	m_fault_string(""),
	m_fired_count(0),
	m_hit_count(0),
	m_line(line),
	m_n_count(0),
	m_fault_mode(fault_mode::ALWAYS),
	m_enabled(false),
	m_probability(100)
{
	fault_handler_registry::instance().register_fault(this);
}

fault_handler::~fault_handler()
{
	fault_handler_registry::instance().deregister_fault(this);
}

bool fault_handler::fired()
{
	++m_hit_count;

	if(!m_enabled)
	{
		return false;
	}

	bool should_fire = false;

	switch(m_fault_mode)
	{
	case fault_mode::ALWAYS:
		should_fire = true;
		break;

	case fault_mode::ONE_SHOT:
		should_fire = (m_fired_count == 0);
		break;

	case fault_mode::PROBABILITY:
		should_fire = (next_rand() <= m_probability);
		break;

	case fault_mode::AFTER_N:
		if(m_n_count == 0)
		{
			should_fire = true;
		}
		else
		{
			--m_n_count;
		}
	}

	if(should_fire)
	{
		++m_fired_count;
	}

	return should_fire;
}

bool fault_handler::fired(const std::function<void(void)>& fn)
{
	if(fired())
	{
		if(fn)
		{
			fn();
		}
		return true;
	}

	return false;
}

bool fault_handler::fired(const std::function<void(const std::string&)>& fn)
{
	if(fired())
	{
		if(fn)
		{
			fn(m_fault_string);
		}
		return true;
	}

	return false;
}

bool fault_handler::fired(const std::function<void(uint64_t)>& fn)
{
	if(fired())
	{
		if(fn)
		{
			fn(m_fault_uint64);
		}
		return true;
	}

	return false;
}

bool fault_handler::fired(const std::function<void(const std::string&, uint64_t)>& fn)
{
	if(fired())
	{
		if(fn)
		{
			fn(m_fault_string, m_fault_uint64);
		}
		return true;
	}

	return false;
}

const std::string& fault_handler::get_fault_string() const
{
	return m_fault_string;
}

uint64_t fault_handler::get_fault_uint64() const
{
	return m_fault_uint64;
}

const std::string& fault_handler::get_filename() const
{
	return m_filename;
}

const std::string& fault_handler::get_name() const
{
	return m_name;
}

uint16_t fault_handler::get_line() const
{
	return m_line;
}

const std::string& fault_handler::get_description() const
{
	return m_description;
}

fault_handler::fault_mode fault_handler::get_fault_mode() const
{
	return m_fault_mode;
}

uint32_t fault_handler::get_fired_count() const
{
	return m_fired_count;
}

uint32_t fault_handler::get_hit_count() const
{
	return m_hit_count;
}

bool fault_handler::is_enabled() const
{
	return m_enabled;
}

uint8_t fault_handler::get_fault_probability() const
{
	return m_probability;
}

void fault_handler::set_fault_probability(const uint8_t value)
{
	m_probability = value;

	if(m_probability > 100)
	{
		m_probability = 100;
	}
}

uint16_t fault_handler::get_n_count() const
{
	return m_n_count;
}

void fault_handler::set_n_count(const uint16_t value)
{
	m_n_count = value;
}

void fault_handler::set_fault_mode(const fault_handler::fault_mode mode)
{
	m_fault_mode = mode;
}

void fault_handler::set_enabled(const bool enabled)
{
	m_enabled = enabled;
}

void fault_handler::set_fault_string(const std::string& value)
{
	m_fault_string = value;
}

void fault_handler::set_fault_uint64(const uint64_t value)
{
	m_fault_uint64 = value;
}

void fault_handler::clear_counters()
{
	m_fired_count = 0;
	m_hit_count = 0;
}

std::string fault_handler::to_json() const
{
	Json::Value root;

	root[m_name]["filename"]     = m_filename;
	root[m_name]["line"]         = m_line;
	root[m_name]["description"]  = m_description;
	root[m_name]["fault_uint64"] = Json::Value::UInt64(m_fault_uint64);
	root[m_name]["fault_string"] = m_fault_string;
	root[m_name]["fired_count"]  = m_fired_count;
	root[m_name]["hit_count"]    = m_hit_count;
	root[m_name]["n_count"]      = m_n_count;
	root[m_name]["enabled"]      = m_enabled;
	root[m_name]["mode"]         = fault_handler::fault_mode_to_string(m_fault_mode);
	root[m_name]["probability"]  = m_probability;

	return root.toStyledString();
}

void fault_handler::from_json(const std::string& json)
{
	Json::Value root;
	Json::Reader reader;

	if(!reader.parse(json, root))
	{
		throw fault_handler::exception("Body contains malformed JSON: " +
		                               reader.getFormattedErrorMessages());
	}

	Json::Value value;

	bool enabled = m_enabled;
	value = root["enabled"];
	if(!value.isNull())
	{
		if(!value.isBool())
		{
			throw fault_handler::exception(
					"'enabled' specified but type not boolean");
		}
		enabled = value.asBool();
	}

	uint64_t fault_uint64 = m_fault_uint64;
	value = root["fault_uint64"];
	if(!value.isNull())
	{
		if(!value.isUInt())
		{
			throw fault_handler::exception(
					"'fault_uint64' specified but type not uint64");
		}
		fault_uint64 = value.asUInt();
	}

	std::string fault_string = m_fault_string;
	value = root["fault_string"];
	if(!value.isNull())
	{
		if(!value.isString())
		{
			throw fault_handler::exception(
					"'fault_string' specified but type not string");
		}
		fault_string = value.asString();
	}

	uint16_t n_count = m_n_count;
	value = root["n_count"];
	if(!value.isNull())
	{
		if(!value.isUInt())
		{
			throw fault_handler::exception(
					"'n_count' specified but type not uint");
		}
		n_count = value.asUInt();
	}

	fault_mode fault_mode = m_fault_mode;
	value = root["mode"];
	if(!value.isNull())
	{
		if(!value.isString())
		{
			throw fault_handler::exception(
					"'mode' specified but type not uint");
		}
		fault_mode = fault_handler::fault_mode_from_string(value.asString());
	}

	uint8_t probability = m_probability;
	value = root["probability"];
	if(!value.isNull())
	{
		if(!value.isUInt())
		{
			throw fault_handler::exception(
					"'probability' specified but type not uint");
		}
		probability = value.asUInt();
		if(probability > 100)
		{
			probability = 100;
		}
	}

	// If we've gotten this far, we haven't run into any errors reading
	// the content from JSON.  Update our fields.
	
	m_enabled = enabled;
	m_fault_uint64 = fault_uint64;
	m_fault_string = fault_string;
	m_n_count = n_count;
	m_fault_mode = fault_mode;
	m_probability = probability;
	m_fired_count = 0;
	m_hit_count = 0;
}

fault_handler::memento_ptr fault_handler::get_state() const
{
	return std::make_shared<concrete_memento>(m_name,
	                                          m_fault_uint64,
	                                          m_fault_string,
	                                          m_fired_count,
	                                          m_hit_count,
	                                          m_n_count,
	                                          m_fault_mode,
	                                          m_enabled,
	                                          m_probability);
}

void fault_handler::restore_state(fault_handler::memento_ptr memento)
{
	if(!memento)
	{
		throw fault_handler::exception("memento cannot be nullptr");
	}

	const concrete_memento* const actual_memento =
		dynamic_cast<concrete_memento*>(memento.get());

	if(actual_memento == nullptr)
	{
		throw fault_handler::exception("memento of unexpected concrete type");
	}

	if(actual_memento->m_name != m_name)
	{
		throw fault_handler::exception("memento is not from this "
		                               "fault_handler instance. "
		                               "this fault: " + m_name +
		                               ", memento name: " +
		                               actual_memento->m_name);
	}

	m_fault_uint64 = actual_memento->m_fault_uint64;
	m_fault_string = actual_memento->m_fault_string;
	m_fired_count  = actual_memento->m_fired_count;
	m_hit_count    = actual_memento->m_hit_count;
	m_n_count      = actual_memento->m_n_count;
	m_fault_mode   = actual_memento->m_fault_mode;
	m_enabled      = actual_memento->m_enabled;
	m_probability  = actual_memento->m_probability;
}

std::string fault_handler::fault_mode_to_string(const fault_mode mode)
{
	std::string str = "UNKNOWN";

	switch(mode)
	{
	case fault_mode::ALWAYS:
		str = ALWAYS;
		break;

	case fault_mode::ONE_SHOT:
		str = ONE_SHOT;
		break;

	case fault_mode::PROBABILITY:
		str = PROBABILITY;
		break;

	case fault_mode::AFTER_N:
		str = AFTER_N;
		break;
	}

	return str;
}

fault_handler::fault_mode fault_handler::fault_mode_from_string(const std::string& str)
{
	fault_mode mode = fault_mode::ALWAYS;

	if(str == ALWAYS)
	{
		mode = fault_mode::ALWAYS;
	}
	else if(str == ONE_SHOT)
	{
		mode = fault_mode::ONE_SHOT;
	}
	else if(str == PROBABILITY)
	{
		mode = fault_mode::PROBABILITY;
	}
	else if(str == AFTER_N)
	{
		mode = fault_mode::AFTER_N;
	}

	return mode;
}

fault_handler::exception::exception(const std::string& message):
	std::runtime_error("fault_handler::exception: " + message)
{ }

#if defined(SYSDIG_TEST)
void fault_handler::seed_random_generator(const unsigned seed)
{
	s_rand_generator = std::default_random_engine(seed);
}
#endif

} // end namespace userspace_shared

#endif
