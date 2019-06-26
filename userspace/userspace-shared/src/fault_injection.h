/**
 * @file
 *
 * General interface to the fault injection framework.
 *
 * This framework enables engineers to define fault injection points, and to
 * perform conditional execution based on the state of those injection points.
 *
 * A simple example:
 *
 * <pre>
 * namespace
 * {
 *
 * DEFINE_FAULT_INJECTOR(fh_some_function_error,
 *                       "agent.some_function.failure",
 *                       "Enables engineers to inject failures into some_function()");
 *
 * }
 *
 * bool some_function()
 * {
 *     ...
 *
 *     if(FAULT_FIRED(fh_some_function_error))
 *     {
 *         return false;
 *     }
 *     return true;
 * }
 *
 * </pre>
 *
 * In the above example, <code>some_function</code> would normally returns
 * true.  If the the fault injection point fires, then it will return false.
 * Note that when fault injection is not build into the system, then
 * FAULT_FIRED evaluates to false, and the compiler will remove the dead
 * code assocaited with the if block.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#if defined(FAULT_INJECTION_ENABLED)
#include "fault_handler.h"

/**
 * Defines a fault handler.
 *
 * @param handler_name  The name of the fault handler
 * @param name          The name of the fault
 * @param description   A description of the use for this injectable fault
 */
#define DEFINE_FAULT_INJECTOR(handler_name, name, description) \
	static userspace_shared::fault_handler handler_name(__FILE__, __LINE__, (name), (description))

/**
 * Determines if the fault associated with the given fault_handler has fired.
 *
 * @param fault_handler The name of the fault_handler that may fire.
 *
 * @returns true if the fault has fired, false otherwise.
 */
#define FAULT_FIRED(fault_handler) \
	(fault_handler).fired()

/**
 * Invokes the given function if the given fault_handler has fired.  The
 * given function can be in one of four forms:
 * <ul>
 *   <li><code>void function()</code></li>
 *   <li><code>void function(const std::string& s)</code></li>
 *   <li><code>void function(uint64_t v)</code></li>
 *   <li><code>void function(const std::string& s, uint64_t v)</code></li>
 * </ul>
 *
 * The first form is useful if you want to perform some action when the
 * fault_handler fires that is independent of the handler's fault_string or
 * fault_uint64.  The second form is useful if you want to perform some action
 * when the fault_handler fires that uses the handler's fault_string.  The
 * third form is similar, but accept's the handler's fault_uint64.  The
 * fourth form, again, is similar, but accepts both the handler's fault_string
 * and fault_uint64.
 *
 * @param fault_handler The name of the fault handler.
 * @param function      The function to invoke if the given fault_handler
 *                      has fired.
 */
#define FAULT_FIRED_INVOKE(fault_handler, function) \
	(fault_handler).fired(function)

/**
 * Return the evaulation of the given expression if the given fault_handler
 * has fired.
 *
 * @param fault_handler The name of the fault handler.
 * @param expr          The value to return if the given fault_handler has
 *                      fired.
 */
#define FAULT_RETURN(fault_handler, expr) \
	do { if(FAULT_FIRED(fault_handler)) { return (expr); } } while(false)

#else // !defined(FAULT_INJECTION_ENABLED)

// If FAULT_INJECTION_ENABLED is not defined, all fault injection macros are
// defined to have no effect.  APIs that accept a default value must evaluate
// to the default value.

// Forward declare a non-existant struct to consume the trailing semicolon
#define DEFINE_FAULT_INJECTOR(fault_handler, name, description) \
	struct DUMMY_FAULT_FORWARD_DECL

#define FAULT_FIRED(fault_handler)                       false
#define FAULT_FIRED_INVOKE(fault_handler, function)      false
#define FAULT_RETURN(fault_handler, expr)

#endif // defined(FAULT_INJECTION_ENABLED)
