#pragma once

#include "sinsp.h"

/**
 * Return a shared_ptr to an instance of sinsp. This class
 * exists so that a mock sinsp can be injected in test code.
 */
namespace sinsp_factory {
	/**
	 * @return the sinsp instance
	 */
	sinsp::ptr build();

#ifdef SYSDIG_TEST
	/**
	 * Inject an instance of sinsp that will be returned the next
	 * time build() is called.
	 */
	void inject(const sinsp::ptr &value);
#endif // SYSDIG_TEST

}