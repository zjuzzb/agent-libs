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

#if defined(SYSDIG_TEST)
void fault_handler::seed_random_generator(const unsigned seed)
{
	s_rand_generator = std::default_random_engine(seed);
}
#endif

} // end namespace userspace_shared

#endif
