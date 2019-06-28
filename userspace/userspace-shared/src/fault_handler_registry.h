/**
 * @file
 *
 * Interface to fault_handler_registry.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once
#if defined(FAULT_INJECTION_ENABLED)

#include <stdexcept>
#include <string>

namespace userspace_shared
{

class fault_handler;

/**
 * A central registry to access all of fault_handler%s defined within the
 * system.
 */
class fault_handler_registry
{
public:
	class exception : public std::runtime_error
	{
	public:
		exception(const std::string& msg);
	};

	/**
	 * Returns the singleton instance of the fault_handler_registry.
	 */
	static fault_handler_registry& instance();

	/**
	 * Register the given fault with the fault registry.
	 *
	 * @param[in] fault The fault to add to the registry.
	 */
	void register_fault(fault_handler* fault);

	/**
	 * Deregister the given fault with the fault registry.
	 *
	 * @param[in] fault The fault to remove from the registry.
	 */
	void deregister_fault(fault_handler* fault);

	/**
	 * Finds and returns a pointer to a registered fault with the given
	 * name.
	 *
	 * @param[in] name The name of the fault to find
	 *
	 * @returns a pointer to the registered fault with the given name or
	 *          nullptr if no fault with the given name is registered.
	 */
	fault_handler* find(const std::string& name);

	/**
	 * Returns a JSON-formatted representation of all registered fault
	 * injection points.
	 */
	std::string to_json() const;
private:
	fault_handler_registry() = default;
	fault_handler_registry(const fault_handler_registry&) = delete;
	fault_handler_registry(fault_handler_registry&&) = delete;
	fault_handler_registry& operator=(const fault_handler_registry&) = delete;
	fault_handler_registry& operator=(const fault_handler_registry&&) = delete;

	static fault_handler_registry* s_instance;

};

} // end namespace userspace_shared

#endif /* defined(FAULT_INJECTION_ENABLED) */
