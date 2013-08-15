//
// Event storage class.
// Used to store temporary event copies.
//
class sisnsp_event_buff
{
public:
	sisnsp_event_buff(sinsp* inspector);
	void store(sinsp_evt* evt);

	char m_data[SP_EVT_BUF_SIZE];
	sinsp_evt m_event;
};
