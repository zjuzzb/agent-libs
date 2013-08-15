#pragma once

class sinsp_evttables;

///////////////////////////////////////////////////////////////////////////////
// Initializer class.
// An instance of this class is created when the library is loaded.
// ONE-SHOT INIT-TIME OPERATIONS SHOULD BE DONE IN THE CONSTRUCTOR OF THIS
// CLASS TO KEEP THEM UNDER A SINGLE PLACE.
///////////////////////////////////////////////////////////////////////////////
class sinsp_initializer
{
public:
	sinsp_initializer();
};

///////////////////////////////////////////////////////////////////////////////
// A simple class to manage pre-allocated objects in a LIFO
// fashion and make sure all of them are deleted upon destruction.
///////////////////////////////////////////////////////////////////////////////
template<typename OBJ> 
class simple_lifo_queue
{
public:
	void add(OBJ* newentry)
	{
		m_full_list.push_back(newentry);
		m_avail_list.push_back(newentry);
	}

	void push(OBJ* newentry)
	{
		m_avail_list.push_front(newentry);
	}

	OBJ* pop()
	{
		if(m_avail_list.empty())
		{
			return NULL;
		}

		OBJ* head = m_avail_list.front();
		m_avail_list.pop_front();
		return head;
	}

	bool empty()
	{
		return m_avail_list.empty();
	}

private:
	list<OBJ*> m_avail_list;
	list<OBJ*> m_full_list;
};

///////////////////////////////////////////////////////////////////////////////
// Hashing support for stl pairs
///////////////////////////////////////////////////////////////////////////////
template <class T>
inline void hash_combine(std::size_t & seed, const T & v)
{
  std::hash<T> hasher;
  seed ^= hasher(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
}

namespace std
{
  template<typename S, typename T> struct hash<pair<S, T>>
  {
    inline size_t operator()(const pair<S, T> & v) const
    {
      size_t seed = 0;
      ::hash_combine(seed, v.first);
      ::hash_combine(seed, v.second);
      return seed;
    }
  };
}

///////////////////////////////////////////////////////////////////////////////
// Hashing support for ipv4tuple
// XXX for the moment, this has not been optimized for performance
///////////////////////////////////////////////////////////////////////////////
struct ip4t_hash
{
	size_t operator()(ipv4tuple t) const
	{
		size_t seed = 0;

		std::hash<uint64_t> hasher64;
		std::hash<uint32_t> hasher32;
		std::hash<uint8_t> hasher8;

		seed ^= hasher64(*(uint64_t*)t.m_all) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
		seed ^= hasher32(*(uint32_t*)(t.m_all + 8)) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
		seed ^= hasher8(*(uint8_t*)(t.m_all + 12)) + 0x9e3779b9 + (seed << 6) + (seed >> 2);

		return seed;
	}
};

struct ip4t_cmp
{
	bool operator () (ipv4tuple t1, ipv4tuple t2) const
	{
		return (memcmp(t1.m_all, t2.m_all, sizeof(t1.m_all)) == 0);
	}
};

///////////////////////////////////////////////////////////////////////////////
// Hashing support for unix_tuple
// not yet optimized
///////////////////////////////////////////////////////////////////////////////
struct unixt_hash
{
	size_t operator()(unix_tuple t) const
	{
		size_t seed = 0;

		std::hash<uint64_t> hasher64;

		seed ^= hasher64(*(uint64_t*)t.m_all) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
		seed ^= hasher64(*(uint64_t*)(t.m_all + 8)) + 0x9e3779b9 + (seed << 6) + (seed >> 2);

		return seed;
	}
};

struct unixt_cmp
{
	bool operator () (unix_tuple t1, unix_tuple t2) const
	{
		return (memcmp(t1.m_all, t2.m_all, sizeof(t1.m_all)) == 0);
	}
};

///////////////////////////////////////////////////////////////////////////////
// A collection of useful functions
///////////////////////////////////////////////////////////////////////////////
class sinsp_utils
{
public:
	//
	// Convert an errno number into the corresponding compact code
	//
	static const char* errno_to_str(int32_t code);

	//
	// Convert a signal number into the corresponding signal name
	//
	static const char* signal_to_str(uint8_t code);

	//
	// Concatenate two paths and puts the result in "target".
	// If path2 is relative, the concatenation happens and the result is true.
	// If path2 is absolute, the concatenation does not happen, target contains path2 and the result is false.
	// Assumes that path1 is well formed. 
	//
	static bool concatenate_paths(char* target, uint32_t targetlen, const char* path1, uint32_t len1, const char* path2, uint32_t len2); 
};

///////////////////////////////////////////////////////////////////////////////
// little STL thing to sanitize strings
///////////////////////////////////////////////////////////////////////////////
struct g_invalidchar
{
    bool operator()(char c) const 
	{
		if(c < -1 || c > 255)
		{
			return true;
		}

		return !isprint((unsigned)c);
    }
};

///////////////////////////////////////////////////////////////////////////////
// Time functions for Windows
///////////////////////////////////////////////////////////////////////////////
#ifdef _WIN32
struct timezone2 
{
	__int32  tz_minuteswest;
	bool  tz_dsttime;
};

struct timeval2 {
	__int32    tv_sec;
	__int32    tv_usec;
};

int gettimeofday(struct timeval *tv, struct timezone2 *tz);
#endif // _WIN32

///////////////////////////////////////////////////////////////////////////////
// gethostname wrapper
///////////////////////////////////////////////////////////////////////////////
string sinsp_gethostname();

///////////////////////////////////////////////////////////////////////////////
// tuples to string
///////////////////////////////////////////////////////////////////////////////
string ipv4tuple_to_string(ipv4tuple* tuple);
string ipv6tuple_to_string(_ipv6tuple* tuple);
