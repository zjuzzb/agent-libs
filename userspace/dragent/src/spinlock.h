#pragma once

#include <atomic>

/**
 * A spinlock.
 *
 * Spinlocks are useful in high-contention scenarios where the lock duration
 * is very short. They are much lighter-weight than a mutex and do not
 * suspend the thread in the case of contention.
 */
class spinlock
{
public:
	spinlock(): m_flag(ATOMIC_FLAG_INIT) {}

	/**
	 * Acquire the spinlock. Spins until the lock can be acquired.
	 */
	inline void lock()
	{
		// Spin until the flag moves from false -> true.
		// memory_order_acquire prevents reads and writes from being reordered
		// to before the atomic set.
		while(m_flag.test_and_set(std::memory_order_acquire));
	}

	/**
	 * Releases the spinlock.
	 */
	inline void unlock()
	{
		// memory_order_release prevents reads and writes from being reordered
		// to after the atomic set.
		m_flag.clear(std::memory_order_release);
	}

private:
	std::atomic_flag m_flag;
};

/**
 * Wraps a spinlock for RAII use cases.
 */
class scoped_spinlock
{
public:
	/*
	 * Init the wrapper with a reference to the lock.
	 * @param lock  The lock to acquire / release.
	 */
	scoped_spinlock(spinlock& lock): m_lock(lock)
	{
		m_lock.lock();
	}

	/**
	 * Release the lock
	 */
	~scoped_spinlock()
	{
		m_lock.unlock();
	}
private:
	spinlock& m_lock;
};
