#include <string>
#include <map>
#include <memory>

#include "sinsp.h"
#include "falco_engine.h"

class falco_events {
public:
	falco_events();
	virtual ~falco_events();

	void init(sinsp *inspector, const std::string &machine_id);

	//
	// Generate a user event from the given falco result (which
	// can be NULL). Handles the details of mapping the falco
	// engine priority to a user event priority, assembling the
	// information into a string, and logging the string.
	//
	void generate_user_event(unique_ptr<falco_engine::rule_result> &res);

private:

	//
	// Map falco severity strings to sinsp priority levels
	inline sinsp_logger::event_severity falco_priority_to_severity(std::string &priority);

	sinsp *m_inspector;
	std::string m_machine_id;

	sinsp_evt_formatter *m_container_id_formatter;

	//
	// A cache of previously created formatters. Used to avoid
	// recreating them for duplicate events.
	//
	std::map<std::string,std::shared_ptr<sinsp_evt_formatter>> m_formatter_cache;
};
