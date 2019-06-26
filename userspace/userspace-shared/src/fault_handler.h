/**
 * @file
 *
 * Interface to fault_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once
#if defined(FAULT_INJECTION_ENABLED)

#include <string>
#include <functional>

namespace userspace_shared
{

/**
 * Fault handlers define fault injection points.  Client code interfaces with
 * the fault injection framework through fault handlers.  Each fault injection
 * point has an associated fault handler.  Client code should not reference
 * this class directly, instead client code should use DEFINE_FAULT_INJECTOR().
 */
class fault_handler
{
public:
	/**
	 * The fault modes exposed by fault_handler%s.
	 */
	enum class fault_mode
	{
		/** When enabled, the fault will always fire. */
		ALWAYS,

		/** When enabled, the fault will fire once. */
		ONE_SHOT,

		/**
		 * When enabled, the fault will fire based on the specified
		 * probability.
		 */
		PROBABILITY,

		/**
		 * When enabled, the fault will not fire for the first N times,
		 * then will fire every time thereafter.
		 */
		AFTER_N,
	};

	/**
	 * Initialize a new fault_handler and register this fault_handler with
	 * the fault_handler_registry.
	 *
	 * @param[in] filename    The name of the file in which the
	 *                        fault_handler is defined.
	 * @param[in] line        The line number on which the fault_handler is
	 *                        defined.
	 * @param[in] name        The name of the fault_handler.
	 * @param[in] description The description of the fault_handler.
	 */
	fault_handler(const std::string& filename,
	              uint16_t line,
	              const std::string& name,
	              const std::string& description);

	fault_handler(const fault_handler&) = delete;
	fault_handler(fault_handler&&) = delete;
	fault_handler& operator=(const fault_handler&) = delete;
	fault_handler& operator=(const fault_handler&&) = delete;

	/**
	 * Deregister this fault_handler with the fault_handler_registry.
	 */
	~fault_handler();

	/**
	 * Returns the name of the file in which this fault_handler is defined.
	 */
	const std::string& get_filename() const;

	/**
	 * Returns the globally-unique name of this fault_handler.
	 */
	const std::string& get_name() const;

	/**
	 * Returns the line number on which this fault_handler is defined.
	 */
	uint16_t get_line() const;

	/**
	 * Returns the description of this fault_handler.
	 */
	const std::string& get_description() const;

	/**
	 * Determines if this fault_handler has fired.  A fault_handler will
	 * fire based on whether it is enabled and the configured fault_mode.
	 *
	 * @returns true if the fault fired, false otherwise.
	 */
	bool fired();

	/**
	 * If this fault_handler fired, invokes the given fn; otherwise
	 * does nothing.  If the given fn is empty, then this fault_handler
	 * will not attempt to call it.
	 *
	 * @returns true if this handler fired, false otherwise.
	 */
	bool fired(const std::function<void(void)>& fn);

	/**
	 * If this fault_handler fired, invokes the given fn; this fault_handler
	 * will pass the current fault_string as an argument to the given fn.
	 * If this fault_handler did not fire, this method does nothing.
	 *
	 * @returns true if this handler fired, false otherwise.
	 */
	bool fired(const std::function<void(const std::string& fault_string)>& fn);

	/**
	 * If this fault_handler fired, invokes the given fn; this fault_handler
	 * will pass the current fault_uint64 as an argument to the given fn.
	 * If this fault_handler did not fire, this method does nothing.
	 *
	 * @returns true if this handler fired, false otherwise.
	 */
	bool fired(const std::function<void(uint64_t fault_uint64)>& fn);

	/**
	 * If this fault_handler fired, invokes the given fn; this fault_handler
	 * will pass the current fault_string and fault_uint64 as an arguments
	 * to the given fn.  If this fault_handler did not fire, this method
	 * does nothing.
	 *
	 * @returns true if this handler fired, false otherwise.
	 */
	bool fired(const std::function<void(const std::string& fault_string,
	                                    uint64_t fault_uint64)>& fn);

	/**
	 * Returns the fault string associated with this fault_handler.
	 */
	const std::string& get_fault_string() const;

	/**
	 * Sets the fault string to the given value.
	 *
	 * @param[in] value The new fault string value.
	 */
	void set_fault_string(const std::string& value);

	/**
	 * Returns the fault uint64 associated with this fault_handler.
	 */
	uint64_t get_fault_uint64() const;

	/**
	 * Sets the value of the uint64 fault value to the given new_value.
	 *
	 * @param[in] new_value The new uint64 fault value.
	 */
	void set_fault_uint64(uint64_t new_value);

	/**
	 * Returns the fault mode of this fault_handler.
	 */
	fault_mode get_fault_mode() const;

	/**
	 * Sets the fault_mode for this fault_handler.
	 *
	 * @param[in] mode The new fault mode for this fault_handler.
	 */
	void set_fault_mode(fault_mode mode);

	/**
	 * Returns the number of times this fault_handler has fired since it
	 * was last reset.
	 */
	uint32_t get_fired_count() const;

	/**
	 * Returns the number of times this fault_handler has been hit since
	 * it was last reset.
	 */
	uint32_t get_hit_count() const;

	/**
	 * Returns true if this fault_handler is enabled, false otherwise.
	 */
	bool is_enabled() const;

	/**
	 * Enables or disables this fault_handler.
	 *
	 * @param[in] enabled if true, enables this fault_handler; otherwise,
	 *                    disables this fault_handler.
	 */
	void set_enabled(bool enabled);

	/**
	 * Returns the fault_probablity [0, 100] for this fault_handler.
	 */
	uint8_t get_fault_probability() const;

	/**
	 * Sets the fault_probablity for this fault_handler to the given
	 * probability.
	 *
	 * @param[in] probability The new fault probability.  If the value
	 *                        is greater than 100, the value will be set
	 *                        to 100.
	 */
	void set_fault_probability(uint8_t probability);

	/**
	 * Returns the N-count counter.  When the fault_mode is AFTER_N,
	 * this value represent the number of times this fault_handler will
	 * not fire before it starts to fire.
	 */
	uint16_t get_n_count() const;

	/**
	 * Sets the N-counter.
	 */
	void set_n_count(uint16_t n_count);

	/**
	 * Clears the fired_count and hit_count counters.
	 */
	void clear_counters();

	/**
	 * Returns a string representation of the given fault mode.
	 *
	 * @param[in] mode The fault_mode for which the client wants a
	 *                 string representation.
	 */
	static std::string fault_mode_to_string(fault_mode mode);

	/**
	 * Returns the fault_mode corresponding to the given str.  If the
	 * given str doesn't correspond to a known fault_mode, this will
	 * returns fault_mode::ALWAYS.
	 *
	 * @param[in] str The string representation of a fault mode.
	 */
	static fault_mode fault_mode_from_string(const std::string& str);

#if defined(SYSDIG_TEST)
	/**
	 * Enable unit tests to seed the underlying random generator with
	 * constant values for consistent results.
	 */
	static void seed_random_generator(unsigned seed = 0);
#endif

private:
	/**
	 * The value to return from get_fault_uint64 if this fault is enabled
	 * and if it fires in that method.
	 */
	uint64_t m_fault_uint64;

	/** The name of the file in which this handler is defined. */
	const std::string m_filename;

	/** The user-defined name of this fault; must be globally unique. */
	const std::string m_name;

	/** The user-defined description of this fault. */
	const std::string m_description;

	/**
	 * The value to return from get_fault_string if this fault is enabled
	 * and if it fires in that method.
	 */
	std::string m_fault_string;

	/** Number of times this fault_handler has fired since last change. */
	mutable uint32_t m_fired_count;

	/** Number of times has this fault_handler been hit since last change. */
	mutable uint32_t m_hit_count;

	/** The line number on which this handler is defined. */
	const uint16_t m_line;

	/**
	 * Used in conjuction with fault_mode::AFTER_N -- specifies how many
	 * times this fault_handler should not fire before it fires.
	 */
	uint16_t m_n_count;

	/** The fault mode of this fault_handler. */
	fault_mode m_fault_mode;

	/** Is this fault_handler enabled?. */
	bool m_enabled;

	/**
	 * If m_fault_mode is fault_mode::PROBABILITY, the probability that
	 * this fault_handler will fire when it is enabled; valid values
	 * are [0, 100].
	 */
	uint8_t m_probability;
};

} // namespace userspace_shared

#endif /* FAULT_INJECTION_ENABLED */
