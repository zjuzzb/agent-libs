//
// The protocol sample header
//
#if defined _MSC_VER
#pragma pack(push)
#pragma pack(1)
#else
#pragma pack(push, 1)
#endif
typedef struct sinsp_sample_header
{
	uint32_t m_sample_len; // length of the whole sample, including this header
	uint8_t m_version; // protocol version
	uint8_t m_messagetype;
} sinsp_sample_header;
#pragma pack(pop)
