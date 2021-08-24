//
// Created by vadimz on 5/24/21.
//

#include "secure_netsec_util.h"

#include "secure_netsec.h"
#include "secure_netsec_cg.h"
#include "secure_netsec_cidr.h"

COMMON_LOGGER();

bool conn_message_split::is_command_filtered(const string& cmd)
{
	static auto bl = secure_netsec::c_secure_netsec_filtered_process_names.get_value();
	static auto last_read = infra_clock::now();

	// reread once in 10 sec
	if (infra_clock::now() - last_read > std::chrono::seconds(10))
	{
		last_read = infra_clock::now();
		bl = secure_netsec::c_secure_netsec_filtered_process_names.get_value();
	}
	return std::find(bl.begin(), bl.end(), cmd) != bl.end();
}

bool conn_message_split::is_in_cidr(const secure_netsec_cidr& cidr) const
{
	return cidr.is_addr_in_k8s_cidr(get_ip_int());
}

netsec_cg_ptr_t conn_message_split::find_pod_by_ip(const infrastructure_state& infra) const
{
	return secure_netsec_util::find_pod_by_ip(infra, get_ip_str());
}

netsec_cg_ptr_t conn_message_split::find_pod_by_container(const infrastructure_state& infra) const
{
	return secure_netsec_util::find_pod_by_container(infra, get_container_id());
}

netsec_cg_ptr_t conn_message_split::find_pod_by_pcontainer(const infrastructure_state& infra) const
{
	return secure_netsec_util::find_pod_by_container(infra, get_ptifo_container_id());
}

netsec_cg_ptr_t conn_message_split::find_pod_by_ccontainer(const infrastructure_state& infra) const
{
	return secure_netsec_util::find_pod_by_container(infra, get_ctifo_container_id());
}

bool conn_message_split::is_node_ip(const infrastructure_state& infra) const
{
	bool found = false;
	auto f_cg = [&found](const cg_ptr_t& cg, const std::string& ip, infra_time_point_t tp)
	{
		const auto& kind = cg->uid().kind();
		found |= (kind == k8s_kind_node || kind == kind_node);
	};
	infra.find_clbk_cgs_by_ip(get_ip_str(), f_cg);
	return found;
}

std::string conn_message_split::to_string(const infrastructure_state& infra) const
{
	auto ip_pod = find_pod_by_ip(infra);
	auto ip_own = ip_pod != nullptr ? ip_pod->get_k8s_owner() : nullptr;

	auto mcont_pod = find_pod_by_container(infra);
	auto mcont_own = mcont_pod != nullptr ? mcont_pod->get_k8s_owner() : nullptr;

	auto pcont_pod = find_pod_by_pcontainer(infra);
	auto pcont_own = pcont_pod != nullptr ? pcont_pod->get_k8s_owner() : nullptr;

	auto cont_pod = find_pod_by_ccontainer(infra);
	auto cont_own = cont_pod != nullptr ? cont_pod->get_k8s_owner() : nullptr;

	std::stringstream ss;
	auto f = [&ss](const char* px, const std::string& cont_id, secure_netsec_cg* pod, secure::K8SPodOwner* owner) -> std::stringstream& {
		ss
		    << "\t" << px << "_cont_pod = " << (pod == nullptr ? "null" : pod->get()->uid().id()) << "\n"
			<< "\tm_cont_own = " << (owner == nullptr ? "null" : (owner->metadata().uid()  + "(" + owner->metadata().name() + ")")) << "\n";
		return ss;
	};

	ss << "\tip = " << get_ip_str() << "(" << get_ip_int() << "):" <<  get_port()  <<"\n"
	   << "\tcomm = " << get_command() << "\n"
	   << "\tip_pod = " << (ip_pod == nullptr ? "null" : ip_pod->get()->uid().id() ) << "\n"
	   << "\tip_own = " << (ip_own == nullptr ? "null" : (ip_own->metadata().uid() + "(" + ip_own->metadata().name() + ")")) << "\n";

		f("main", get_container_id(), mcont_pod.get(), mcont_own.get());
		f("par", get_ptifo_container_id(), pcont_pod.get(), pcont_own.get());
		f("curr", get_ctifo_container_id(), cont_pod.get(), cont_own.get());


	return ss.str();
}

netsec_cg_ptr_t secure_netsec_util::find_pod_by_ip(const infrastructure_state& infra,
                                                   const std::string& ip)
{
	netsec_cg_ptr_t ret;
	bool found = false;
	auto f = [&](const cg_ptr_t& cg, const std::string& ip, infra_time_point_t cg_inserted_at)
	{
		auto cg_wrap = make_unique<secure_netsec_cg>(infra, cg);
		if (!cg_wrap->is_pod())
		{
			return;
		}
		if (!found)
		{
			ret = std::move(cg_wrap);
			found = true;
		}
	};
	infra.find_clbk_cgs_by_ip(ip, f);
	return ret;
}

netsec_cg_ptr_t secure_netsec_util::find_pod_by_container(const infrastructure_state& infra,
                                                          const std::string& cont_id)
{
	netsec_cg_ptr_t ret;
	int cnt = 0;  // just a safe guard
	auto cf = [&](const cg_ptr_t& cg)
	{
		if (++cnt < 2)
		{
			ret.reset(new secure_netsec_cg(infra, cg));
		}
		else
		{
			LOG_ERROR("container '%s' belongs to more than one pod", cont_id.c_str());

		}
	};
	infra.find_clbk_container_pod(cont_id, cf);
	return ret;
}
