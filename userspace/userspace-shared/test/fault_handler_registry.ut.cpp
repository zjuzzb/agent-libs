/**
 * @file
 *
 * Unit tests for fault_handler_registry.
 *
 * @copyright Copyright (c) 2019 Sysdig, Inc., All Rights Reserved
 */
#if defined(FAULT_INJECTION_ENABLED)

#include "fault_handler_registry.h"
#include "fault_handler.h"
#include <gtest.h>

using namespace userspace_shared;

namespace
{

const std::string FILENAME = "foo.cpp";
const uint16_t LINE = 18;
const std::string NAME = "this.that";
const std::string DESCRIPTION = "some description";

} // end namespace


/**
 * Ensure that before a fault_handler is created, that it isn't in the
 * registry.  Ensure that after a fault_handler is created, that it is
 * automatically added to the registry and that find() returns its address.
 * Ensure that after a fault_handler is destroyed, that it is automatically
 * removed from the registry and that find() can no longer find it.
 */
TEST(fault_handler_registry_test, register_deregister_find)
{
	ASSERT_EQ(nullptr, fault_handler_registry::instance().find(NAME));
	{
		fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

		ASSERT_EQ(&fh, fault_handler_registry::instance().find(NAME));
	}
	ASSERT_EQ(nullptr, fault_handler_registry::instance().find(NAME));
}

/**
 * Ensure that calling register_fault() with nullptr triggers an exception.
 */
TEST(fault_handler_registry_test, register_nullptr_exception)
{
	ASSERT_THROW({
		fault_handler_registry::instance().register_fault(nullptr);
	}, fault_handler_registry::exception);
}

/**
 * Ensure that calling deregister_fault() with nullptr triggers an exception.
 */
TEST(fault_handler_registry_test, deregister_nullptr_exception)
{
	ASSERT_THROW({
		fault_handler_registry::instance().deregister_fault(nullptr);
	}, fault_handler_registry::exception);
}

/**
 * Ensure that trying to register two fault_handler%s with the same name
 * triggers an exception.
 */
TEST(fault_handler_registry_test, double_registration_exception)
{
	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

	ASSERT_THROW({
		fault_handler fh2(FILENAME, LINE, NAME, DESCRIPTION);
	}, fault_handler_registry::exception);
}

#endif /* defined(FAULT_INJECTION_ENABLED) */
