#pragma once

#include "common_logger.h"
#include "common_assert.h"
#include "sinsp.h"

#include <memory>
#include <string>

struct stat;

class capture;

/**
 * @brief A reader for capture files
 *
 * `capture_reader` owns the fd used to read the capture and ensures it gets
 * closed when the reader is destroyed. This means whoever creates
 * a `capture_reader` *must not* close the fd.
 *
 * The only two operations exposed are:
 * - read up to `n` bytes into a caller-provided buffer
 * - stat() the file
 *
 * Instances of `capture_reader` cannot be copied, only moved.
 */
class capture_reader
{
	/**
	 * Create a new `capture_reader`, reading from `read_fd`.
	 * It takes ownership of the fd, so the caller must not
	 * close it manually.
	 */
	explicit capture_reader(int read_fd): m_read_fd(read_fd) {}
public:

	capture_reader(const capture_reader& rhs) = delete;

	capture_reader(capture_reader&& rhs) noexcept
	    : m_read_fd(rhs.m_read_fd)
	{
		rhs.m_read_fd = -1;
	}

	virtual ~capture_reader();

	/**
	 * @brief Read data from the capture
	 * @param buf the target buffer
	 * @param size size of the buffer
	 * @return number of bytes read (or -1 on error)
	 *
	 * It's a pass through to `read()` on the underlying fd
	 */
	ssize_t read_back(void* buf, size_t size);

	/**
	 * @brief `stat()` the capture file
	 * @param s output: the `struct stat` with metadata of the capture file
	 * @return 0 on success, -1 on error
	 *
	 * It's a pass through to `stat()` on the underlying fd
	 */
	int stat(struct stat& s);

	capture_reader& operator=(const capture_reader& rhs) = delete;

	inline capture_reader& operator=(capture_reader&& rhs) noexcept
	{
		m_read_fd = rhs.m_read_fd;
		rhs.m_read_fd = -1;
		return *this;
	}

private:
	int m_read_fd;

	// to call the constructor
	friend class capture;
};

/**
 * @brief A class encapsulating a capture being written to
 *
 * It owns the file descriptor for a brief moment, but immediately passes it
 * to the `sinsp_dumper` member.
 *
 * The only way to actually start a capture write is to call the static
 * `start()` method which returns a `unique_ptr`, so you can't get the lifetime
 * wrong unless you try very hard.
 *
 * The basic interface is `dump()` which takes an event and writes it using
 * the dumper.
 *
 * You can also call `make_reader()` to get a `capture_reader` that lets you
 * read back the capture event by event. The reader is a separate object since
 * they have distinct lifetimes: the reader can outlive the writer when we
 * finish writing but still have events to read back.
 *
 * Instances of `capture` cannot be copied, only moved.
 */
class capture
{
	capture() : m_read_fd(-1), m_n_events(0) {}
public:
	capture(const capture& rhs) = delete;

	capture(capture&& rhs) noexcept
	    : m_read_fd(rhs.m_read_fd),
	      m_n_events(rhs.m_n_events.load()),
	      m_dumper(std::move(rhs.m_dumper))
	{
		rhs.m_read_fd = -1;
		rhs.m_n_events = 0;
	}

	virtual ~capture();

	/**
	 * @brief start a new capture write
	 * @param inspector the inspector to use
	 * @param filename the file to write to
	 * @return a new `capture` instance
	 */
	static std::unique_ptr<capture> start(sinsp* inspector, const std::string& filename);

	/**
	 * @brief get a `capture_reader` associated with this writer
	 * @return a new `capture_reader`
	 *
	 * The new reader takes ownership of the read fd opened in `start()`
	 * which means you can only create a single reader from each
	 * `capture`.
	 */
	std::unique_ptr<capture_reader> make_reader();

	/**
	 * @brief Write an event to the dumper
	 * @param evt the event to write
	 */
	inline void dump(sinsp_evt* evt)
	{
		ASSERT(m_dumper != nullptr);
		m_n_events++;
		m_dumper->dump(evt);
	}

	/**
	 * @brief Return the number of events written
	 * @return the number of events written so far
	 */
	inline uint64_t get_num_events() const
	{
		return m_n_events;
	}

	/**
	 * @brief Set the inspector used to write
	 * @param inspector the inspector
	 */
	inline void set_inspector(sinsp* inspector)
	{
		ASSERT(m_dumper != nullptr);
		m_dumper->set_inspector(inspector);
	}

	capture& operator=(const capture& rhs) = delete;

	inline capture& operator=(capture&& rhs) noexcept
	{
		m_read_fd = rhs.m_read_fd;
		m_n_events.store(rhs.m_n_events);
		m_dumper = std::move(rhs.m_dumper);

		rhs.m_read_fd = -1;
		rhs.m_n_events = 0;

		return *this;
	}

private:
	int m_read_fd;
	std::atomic<uint64_t> m_n_events;
	std::unique_ptr<sinsp_dumper> m_dumper;
};
