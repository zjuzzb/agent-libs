#pragma once
#include <unordered_map>
#include <vector>

class hsperfdata_reader
{
public:
	using byte_buffer_t = std::vector<char>;
	static std::string get_jmx_connector_server(byte_buffer_t&& bytes);

private:
	using map_t = std::unordered_map<std::string, std::string>;

	enum class byte_order_t : uint8_t
	{
		BIG_ENDIAN_ORDER
		, LITTLE_ENDIAN_ORDER
	};

	enum class type_code_t : char
	{
		BOOLEAN = 'Z'
		, CHAR    = 'C'
		, FLOAT   = 'F'
		, DOUBLE  = 'D'
		, BYTE    = 'B'
		, SHORT   = 'S'
		, INT     = 'I'
		, LONG    = 'J'
		, OBJECT  = 'L'
		, ARRAY   = '['
		, VOID    = 'V'
	};

	struct perfdata_buffer_prologue_t
	{
		uint32_t magic;
		byte_order_t byte_order;
		uint8_t major_number;
		uint8_t minor_number;
	}__attribute__((packed));

	struct perfdata_bufferprologue_v2_t
	{
		bool accessible;
		int32_t used;
		int32_t overflow;
		int64_t mod_timestamp;
		int32_t entry_offset;
		int32_t num_entries;
	}__attribute__((packed));

	enum class units_t : uint8_t
	{
		INVALID
		, NONE
		, BYTES
		, TICKS
		, EVENTS
		, STRING
		, HERTZ
	};


	enum class variability_t : uint8_t
	{
		INVALID
		, CONSTANT
		, MONOTONIC
		, VARIABLE
	};

	struct perfdata_entry_t {
		int32_t entry_length;
		int32_t name_offset;
		int32_t vector_length;
		type_code_t data_type;
		uint8_t flags;
		units_t data_units;
		variability_t data_var;
		int32_t data_offset;
	}__attribute__((packed));

	static int32_t byte_order_32(const int32_t value, const byte_order_t order);
	static int64_t byte_order_64(const int64_t value, const byte_order_t order);
	static map_t read_hsperfdata(byte_buffer_t&& bytes);

};
