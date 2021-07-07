#pragma once

#include "common_logger.h"
#include "common_assert.h"
#include "sinsp.h"

#include <memory>
#include <string>

/**
 * @brief A class encapsulating a capture being written to
 *
 * It owns the file descriptor for a brief moment, but immediately passes it
 * to the `sinsp_dumper` member.
 *
 * The only way to actually start a capture write is to call the static
 * `start()` method which returns a `unique_ptr`, so you can't get the lifetime
 * wrong unless you try very hard.
 *
 * The basic interface is `dump()` which takes an event and writes it using
 * the dumper.
 *
 * Instances of `capture` cannot be copied, only moved.
 */
class capture
{
	capture() : m_n_events(0) {}
public:
	capture(const capture& rhs) = delete;

	capture(capture&& rhs) noexcept
	    : m_n_events(rhs.m_n_events.load()),
	      m_dumper(std::move(rhs.m_dumper))
	{
		rhs.m_n_events = 0;
	}

	virtual ~capture();

	/**
	 * @brief start a new capture write
	 * @param inspector the inspector to use
	 * @param filename the file to write to
	 * @return a new `capture` instance
	 */
	static std::unique_ptr<capture> start(sinsp* inspector, const std::string& filename);

	/**
	 * @brief Write an event to the dumper
	 * @param evt the event to write
	 */
	inline void dump(sinsp_evt* evt)
	{
		ASSERT(m_dumper != nullptr);
		m_n_events++;
		m_dumper->dump(evt);
	}

	/**
	 * @brief Return the number of events written
	 * @return the number of events written so far
	 */
	inline uint64_t get_num_events() const
	{
		return m_n_events;
	}

	/**
	 * @brief Set the inspector used to write
	 * @param inspector the inspector
	 */
	inline void set_inspector(sinsp* inspector)
	{
		ASSERT(m_dumper != nullptr);
		m_dumper->set_inspector(inspector);
	}

	capture& operator=(const capture& rhs) = delete;

	inline capture& operator=(capture&& rhs) noexcept
	{
		m_n_events.store(rhs.m_n_events);
		m_dumper = std::move(rhs.m_dumper);

		rhs.m_n_events = 0;

		return *this;
	}

private:
	std::atomic<uint64_t> m_n_events;
	std::unique_ptr<sinsp_dumper> m_dumper;
};
