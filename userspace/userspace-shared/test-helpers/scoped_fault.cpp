/**
 * @file
 *
 * Implementation of scoped_fault.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "scoped_fault.h"
#include "fault_handler.h"
#include "fault_handler_registry.h"
#include <stdexcept>

using userspace_shared::fault_handler;
using userspace_shared::fault_handler_registry;

namespace test_helpers
{

scoped_fault::scoped_fault(const std::string& name):
	m_name(name),
	m_memento()
{
	const fault_handler* const f_handler = handler();

	if(f_handler == nullptr)
	{
		throw std::runtime_error("Cannot find handler with name " + name);
	}

	m_memento = f_handler->get_state();
}

scoped_fault::~scoped_fault()
{
	if(m_memento)
	{
		fault_handler* const f_handler = handler();

		if(f_handler != nullptr)
		{
			f_handler->restore_state(m_memento);
		}
	}
}

userspace_shared::fault_handler* scoped_fault::handler()
{
	return fault_handler_registry::instance().find(m_name);
}

} // namespace test_helpers
