#include "hsperfdata_reader.h"
#include "jni_utils.h"

int32_t hsperfdata_reader::byte_order_32(const int32_t value, const byte_order_t order)
{
#   if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        if(order == byte_order_t::BIG_ENDIAN_ORDER)
        {
            return value;
        }
#   else
        if(order == byte_order_t::LITTLE_ENDIAN_ORDER)
        {
            return value;
        }
#   endif
    return __bswap_32(value);
}

int64_t hsperfdata_reader::byte_order_64(const int64_t value, const byte_order_t order)
{
#   if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        if(order == byte_order_t::BIG_ENDIAN_ORDER)
        {
            return value;
        }
#   else
        if(order == byte_order_t::LITTLE_ENDIAN_ORDER)
        {
            return value;
        }
#   endif
    return __bswap_64(value);
}

hsperfdata_reader::map_t hsperfdata_reader::read_hsperfdata(byte_buffer_t&& bytes)
{
	map_t entry_map;
	uint64_t frequency = 0;
	std::unordered_map<std::string, int64_t> unconverted_tick_fields;

	perfdata_buffer_prologue_t* const prologue = reinterpret_cast<perfdata_buffer_prologue_t*>(&bytes[0]);
	prologue->magic = byte_order_32(prologue->magic, byte_order_t::BIG_ENDIAN_ORDER);

	if (prologue->magic == 0xcafec0c0)
	{
		perfdata_bufferprologue_v2_t* const prologueV2 = reinterpret_cast<perfdata_bufferprologue_v2_t*>(&bytes[0] + sizeof(perfdata_buffer_prologue_t));

		prologueV2->used         = byte_order_32(prologueV2->used, prologue->byte_order);
		prologueV2->overflow     = byte_order_32(prologueV2->overflow, prologue->byte_order);
		prologueV2->mod_timestamp = byte_order_64(prologueV2->mod_timestamp, prologue->byte_order);
		prologueV2->entry_offset  = byte_order_32(prologueV2->entry_offset, prologue->byte_order);
		prologueV2->num_entries   = byte_order_32(prologueV2->num_entries, prologue->byte_order);

		int32_t current_offset = prologueV2->entry_offset;

		for(int32_t i = 0; i < prologueV2->num_entries; ++i)
		{
			perfdata_entry_t* const entry = reinterpret_cast<perfdata_entry_t*>(&bytes[0] + current_offset);

			entry->entry_length  = byte_order_32(entry->entry_length, prologue->byte_order);
			entry->name_offset   = byte_order_32(entry->name_offset, prologue->byte_order);
			entry->vector_length = byte_order_32(entry->vector_length, prologue->byte_order);
			entry->data_offset   = byte_order_32(entry->data_offset, prologue->byte_order);

			const std::string name = &bytes[current_offset + entry->name_offset];
			const int32_t dataStart = (current_offset + entry->data_offset);

			if(entry->vector_length == 0)
			{
				if(entry->data_type == type_code_t::LONG)
				{
					const int64_t value = *(int64_t*)(&bytes[dataStart]);

					if (entry->data_units == units_t::TICKS)
					{
						unconverted_tick_fields[name] = value;
					}
					else
					{
						entry_map[name] = std::to_string(value);
					}

					// TODO: Need to make sure this is correct
					if(name == "sun.os.hrt.frequency")
					{
						frequency = 1000000000L / value;
					}
				}
				else
				{
					log("WARNING", "Unexpected type parsing hsperfdata");
				}
			}
			else
			{
				if(entry->data_type == type_code_t::BYTE
				   && entry->data_units == units_t::STRING
				   && (entry->data_var == variability_t::CONSTANT
				       || entry->data_var == variability_t::VARIABLE))
				{
					const std::string value = &bytes[dataStart];
					entry_map[name] = value;

				}
				else
				{
					log("WARNING", "Unexpected type parsing hsperfdata");
				}
			}

			current_offset += entry->entry_length;
		}


		for(const auto& i : unconverted_tick_fields)
		{
			// TODO: Need to make sure this is correct
			entry_map[i.first] = std::to_string(i.second * frequency);
		}
	}
	else
	{
		log("WARNING", "Invalid hsperfdata file");
	}

	return entry_map;
}

std::string hsperfdata_reader::get_jmx_connector_server(byte_buffer_t&& bytes)
{
	auto hsperf_map = read_hsperfdata(std::forward<byte_buffer_t>(bytes));

	std::string ret;
	std::string address;
	std::string name;
	for(auto& el : hsperf_map)
	{
		if(el.first == "sun.management.JMXConnectorServer.address")
		{
			address = el.second;
		}
		else if(el.first == "sun.rt.javaCommand")
		{
			name = el.second;
		}

		if(!address.empty() && !name.empty())
		{
			break;
		}
	}

	if(!address.empty() && !name.empty())
	{
		ret = "{\"address\" : \"" + address + "\",";
		ret += "\"name\" : \"" + name + "\",";
		ret += "\"available\" : true}";
	}

	return ret;
}

