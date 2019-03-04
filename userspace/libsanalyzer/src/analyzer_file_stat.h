#pragma once

#include <algorithm>
#include <functional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace draiosproto {
class file_stat;
}

// File I/O accounting stats
//
// Instances of this class keep track of I/O done to a particular file, i.e.:
// * bytes read/written
// * time taken for read/write
// * syscall error count
// * number of times a particular file was successfully opened
//
// It corresponds 1:1 to the `file_stat` draios.proto message. If m_include_in_sample == false (the default),
// the particular item is not emitted.
//
// Note: this class doesn't know what it keeps stats for. It's supposed to be used in a key-value map,
// where the key is e.g. the path to the file in question. See analyzer_file_stat_map below.
class analyzer_file_stat
{
public:
	analyzer_file_stat() :
		m_time_ns(0),
		m_bytes(0),
		m_errors(0),
		m_open_count(0),
		m_include_in_sample(false)
	{
	}

	inline void account_io(uint32_t bytes, uint64_t time_ns)
	{
		m_bytes += bytes;
		m_time_ns += time_ns;
	}

	inline void account_file_open()
	{
		++m_open_count;
	}

	inline void account_error()
	{
		++m_errors;
	}

	inline analyzer_file_stat &operator+=(const analyzer_file_stat &rhs)
	{
		m_time_ns += rhs.m_time_ns;
		m_bytes += rhs.m_bytes;
		m_errors += rhs.m_errors;
		m_open_count += rhs.m_open_count;
		return *this;
	}

	void to_protobuf(draiosproto::file_stat* protobuf) const;

	static bool cmp_bytes(const analyzer_file_stat& lhs, const analyzer_file_stat& rhs)
	{
		return lhs.m_bytes > rhs.m_bytes;
	}

	static bool cmp_time(const analyzer_file_stat& lhs, const analyzer_file_stat& rhs)
	{
		return lhs.m_time_ns > rhs.m_time_ns;
	}

	static bool cmp_errors(const analyzer_file_stat& lhs, const analyzer_file_stat& rhs)
	{
		return lhs.m_errors > rhs.m_errors;
	}

	static bool cmp_open_count(const analyzer_file_stat& lhs, const analyzer_file_stat& rhs)
	{
		return lhs.m_open_count > rhs.m_open_count;
	}

	inline bool is_included_in_sample() const
	{
		return m_include_in_sample;
	}

	inline void include_in_sample()
	{
		m_include_in_sample = true;
	}

	uint64_t time_ns() const { return m_time_ns; }
	uint32_t bytes() const { return m_bytes; }
	uint32_t errors() const { return m_errors; }
	uint32_t open_count() const { return m_open_count; }

private:
	uint64_t m_time_ns;
	uint32_t m_bytes;
	uint32_t m_errors;
	uint32_t m_open_count;
	bool m_include_in_sample;
};

// Key-value map of file I/O stats
//
// The key is an arbitrary type K (e.g. std::string for file paths) and the value is an analyzer_file_stat instance.
// Most of the interface is just forwarded to the underlying map, others are commented at their declarations
template<class K>
class analyzer_file_stat_map
{
	using items_t = std::vector<std::pair<K, std::reference_wrapper<analyzer_file_stat>>>;
public:
	using map_t = std::unordered_map<K, analyzer_file_stat>;
	using iterator = typename map_t::iterator;
	using const_iterator = typename map_t::const_iterator;

	// Add the map at rhs to ourselves, key by key.
	// This is useful e.g. when combining per-program maps to form a per-container map
	void add(const analyzer_file_stat_map &rhs)
	{
		for(const auto& it : rhs.m_file_stat)
		{
			m_file_stat[it.first] += it.second;
		}
	}

	// forward indexing[], .clear() and iteration to the map inside
	analyzer_file_stat& operator[](const K& key) { return m_file_stat[key]; }
	void clear() { m_file_stat.clear(); }
	size_t size() const { return m_file_stat.size(); }
	iterator begin() { return m_file_stat.begin(); }
	const_iterator begin() const { return m_file_stat.begin(); }
	iterator end() { return m_file_stat.end(); }
	const_iterator end() const { return m_file_stat.end(); }
	iterator find(const K& key) { return m_file_stat.find(key); }
	const_iterator find(const K& key) const { return m_file_stat.find(key); }

protected:
	// only allow instances of subclasses to be instantiated
	// (they realistically need to provide an emit() implementation)
	analyzer_file_stat_map() = default;

	// The underlying method that does all the work to emit top N entries of the map
	// by our chosen (and hardcoded) set of criteria
	//
	// Take top `count` entries by:
	// - read/written byte count
	// - time spent on I/O
	// - error count
	// - successful open count
	// and for each one (i.e. up to 4 times `count` entries):
	// 1. call `new_file_f` to get a new protobuf instance
	// 2. copy the entry to the protobuf
	//
	// `new_file_f` gets passed the map key and is responsible for calling `set_name` with an appropriate value
	// on the resulting protobuf.
	void emit_impl(int count, std::function<draiosproto::file_stat *(const K&)> new_file_f);

private:
	using cmp_pair = std::pair<K, std::reference_wrapper<analyzer_file_stat>>;

	// a helper method to mark the top `count` items sorted by the predicate `F` to be included in the protobufs
	// the input is a vector of pairs that then gets (partially) sorted and the first `count` items
	// are marked for inclusion
	template<bool (*F)(const analyzer_file_stat&, const analyzer_file_stat&)> static void mark_top_n_by(items_t& items, int count)
	{
		std::partial_sort(items.begin(), items.begin() + count, items.end(),
			[&](const cmp_pair& lhs, const cmp_pair& rhs) {
				return F(lhs.second, rhs.second);
			}
		);

		for(uint32_t j = 0; j < count; j++)
		{
			items[j].second.get().include_in_sample();
		}
	}

	map_t m_file_stat;
};

template<class K>
void analyzer_file_stat_map<K>::emit_impl(int count, std::function<draiosproto::file_stat *(const K&)> new_file_f)
{
	if(m_file_stat.size() <= count)
	{
		// the limit is smaller than the number of entries, so just emit all of them
		for(const auto& it : m_file_stat)
		{
			draiosproto::file_stat* top_file = new_file_f(it.first);
			if (top_file)
			{
				it.second.to_protobuf(top_file);
			}
		}
	}
	else
	{
		// convert the map to a vector of (key, value) pairs
		std::vector<std::pair<K, std::reference_wrapper<analyzer_file_stat>>> files_sortable_list;
		for(auto& it : m_file_stat)
		{
			files_sortable_list.push_back(std::make_pair(it.first, std::ref(it.second)));
		}

		// mark entries to be emitted
		mark_top_n_by<analyzer_file_stat::cmp_bytes>(files_sortable_list, count);
		mark_top_n_by<analyzer_file_stat::cmp_time>(files_sortable_list, count);
		mark_top_n_by<analyzer_file_stat::cmp_errors>(files_sortable_list, count);
		mark_top_n_by<analyzer_file_stat::cmp_open_count>(files_sortable_list, count);

		// and emit the marked ones
		for(const auto& it : files_sortable_list)
		{
			if(it.second.get().is_included_in_sample())
			{
				draiosproto::file_stat* top_file = new_file_f(it.first);
				if (top_file)
				{
					it.second.get().to_protobuf(top_file);
				}
			}
		}
	}
}

// A concrete class to store per-file I/O stats (the key is the full path to the file)
// It's a template as we're using instances of this class at various points of the protobuf
// for per-program, per-container and per-host top file metrics
//
// All the parent protobuf messages have different types but the field is always called
// `top_files`, so we can handle them all with one template
class analyzer_top_file_stat_map : public analyzer_file_stat_map<std::string>
{
public:
	template<class P> void emit(P* protobuf, int count)
	{
		emit_impl(count, [&](const std::string& name) {
			auto pb = protobuf->add_top_files();
			pb->set_name(name);
			return pb;
		});
	}
};
