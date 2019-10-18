#pragma once

#include <memory>

namespace test_helpers
{

/**
 * For legacy reasons, the inspector must be deleted before the analyzer.
 * One approach is to add a call to inspector.reset() at the end of the
 * enclosing scope.  That works as long as the flow of control hits that
 * statement.  If, however, there's an early return (e.g., when a test
 * fails), then the call to reset() is skipped and the test binary crashes.
 *
 * This class wraps the call to reset.  If you create an instance of this
 * after creating the analyzer, then it will get destroyed before the
 * analyzer --- no matter what flow triggers the destruction --- before the
 * analyzer gets destroyed.
 *
 * <pre>
 * std::unique_ptr<sinsp_mock> inspector(...);
 * sinsp_analyzer analyzer(inspector.get(), ...);
 * unique_ptr_resetter<sinsp_mock> resetter(inspector);
 * ...
 * <pre>
 */
template<typename T>
class unique_ptr_resetter
{
public:
	unique_ptr_resetter(std::unique_ptr<T> &ptr):
		m_ptr(ptr)
	{
	}

	~unique_ptr_resetter()
	{
		m_ptr.reset();
	}

private:
	std::unique_ptr<T> &m_ptr;
};
} // namespace test_helpers