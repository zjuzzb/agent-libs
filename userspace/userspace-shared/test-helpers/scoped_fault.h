/**
 * @file
 *
 * Interface to scoped_fault.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include "fault_handler.h"
#include <string>

namespace test_helpers
{

/**
 * A scoped_fault saves the state of a fault_handler on construction and
 * restores that fault_handler's state on destruction.
 */
class scoped_fault
{
public:
	/**
	 * Saves the state of the fault with the given name.  If no fault with
	 * the given name exists, this will throw a std::runtime_error.
	 *
	 * @param[in] name The name of the fault whose state should be saved.
	 */
	scoped_fault(const std::string& name);

	/**
	 * Restores the state of the fault.
	 */
	~scoped_fault();

private:
	std::string m_name;
	userspace_shared::fault_handler::memento_ptr m_memento;
};

} // namespace test_helpers
