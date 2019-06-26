/**
 * @file
 *
 * Implementation of fault_handler_registry.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#if defined(FAULT_INJECTION_ENABLED)

#include "fault_handler_registry.h"
#include "fault_handler.h"
#include <assert.h>
#include <map>
#include <string>

namespace
{

typedef std::map<std::string, userspace_shared::fault_handler*> fault_map;

/**
 * Returns a reference to a singleton fault_map instance.
 */
fault_map& get_map()
{
	// Note that I dynamically allocate this so that we don't have to
	// worry about static deinitialization at program shutdown
	static fault_map* fmap = nullptr;

	if(fmap == nullptr)
	{
		fmap = new fault_map();
	}

	return *fmap;
}

} // end namespace

namespace userspace_shared
{

fault_handler_registry* fault_handler_registry::s_instance;

fault_handler_registry& fault_handler_registry::instance()
{
	if(s_instance == nullptr)
	{
		s_instance = new fault_handler_registry();
	}

	return *s_instance;
}

void fault_handler_registry::register_fault(fault_handler* const fault)
{
	if(fault == nullptr)
	{
		throw fault_handler_registry::exception(
				"register_fault: Null fault handler");
	}

	if(get_map().find(fault->get_name()) != get_map().end())
	{
		throw fault_handler_registry::exception(
				"register_fault: Duplicate fault name: " +
				fault->get_name());
	}

	get_map()[fault->get_name()] = fault;
}

void fault_handler_registry::deregister_fault(fault_handler* const fault)
{
	if(fault == nullptr)
	{
		throw fault_handler_registry::exception(
				"deregister_fault: Null fault handler");
	}

	get_map().erase(fault->get_name());
}

fault_handler* fault_handler_registry::find(const std::string& name)
{
	fault_handler* handler = nullptr;
	fault_map::const_iterator itr = get_map().find(name);

	if(itr != get_map().end())
	{
		handler = itr->second;
	}

	return handler;
}

fault_handler_registry::exception::exception(const std::string& msg):
	std::runtime_error("fault_handler_registry_exception: " + msg)
{ }

} // end namespace userspace_shared

#endif /* defined(FAULT_INJECTION_ENABLED) */
