#include "user_event_channel.h"
#include "Poco/Message.h"

user_event_channel::user_event_channel(): m_event_queue(new user_event_queue())
{
}

user_event_channel::~user_event_channel()
{
}
