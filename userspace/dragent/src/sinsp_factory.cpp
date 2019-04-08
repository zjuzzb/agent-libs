#include "sinsp_factory.h"


#ifndef SYSDIG_TEST

// The production version just returns a new sinsp
namespace sinsp_factory
{

sinsp::ptr build()
{
	return sinsp::ptr(new sinsp());
}

}

#else // SYSDIG_TEST

namespace
{

sinsp::ptr s_test_sinsp;

}

// The test version allows the client to inject a fake sinsp instance
namespace sinsp_factory
{

void inject(const sinsp::ptr& value)
{
	s_test_sinsp = value;
}

sinsp::ptr build()
{
	if(s_test_sinsp)
	{
		sinsp::ptr temp = s_test_sinsp;
		s_test_sinsp.reset();
		return temp;
	}

	return sinsp::ptr(new sinsp());
}

} // namespace sinsp_factory

#endif // SYSDIG_TEST

