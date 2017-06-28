#ifndef ORCHESTRATOR_STATE_H
#define ORCHESTRATOR_STATE_H

#include <map>

#include "sinsp.h"
#include "sinsp_int.h"
#include "sinsp_errno.h"
#include "sinsp_signal.h"
#include "analyzer_utils.h"
#include "coclient.h"

class orchestrator_state
{
public:
	using uid_t = std::pair<std::string, std::string>;
	using state_t = std::map<uid_t, std::unique_ptr<draiosproto::container_group>>;

	orchestrator_state(uint64_t refresh_interval);

	~orchestrator_state();

	void refresh();

private:

	void handle_event(sdc_internal::congroup_update_event *evt);

	void connect(orchestrator_state::uid_t& key);
	void remove(sdc_internal::congroup_update_event *evt);

	state_t m_state;

	coclient m_coclient;
	coclient::response_cb_t m_callback;
	run_on_interval m_interval;

};

#endif // ORCHESTRATOR_STATE_H
