#include <iostream>
#include <sinsp.h>
#include <sinsp_int.h>
#include "utils.h"
#include "draios.pb.h"
#include <baseliner.h>

///////////////////////////////////////////////////////////////////////////////
// sisnp_baseliner implementation
///////////////////////////////////////////////////////////////////////////////
void sisnp_baseliner::init(sinsp* inspector)
{
	m_inspector = inspector;
	m_ifaddr_list = m_inspector->get_ifaddr_list();
	load_tables();
	const scap_machine_info* minfo = m_inspector->get_machine_info();
	m_hostname = minfo->hostname;
	m_hostid = 12345;	// XXX implement this
}

void sisnp_baseliner::load_tables()
{
	init_containers();
	init_programs();
}

void sisnp_baseliner::clear_tables()
{
	m_progtable.clear();
	m_container_table.clear();
}

void sisnp_baseliner::init_programs()
{
	//
	// Go through the thread list and identify the main threads
	//
	for(auto it = m_inspector->m_thread_manager->m_threadtable.begin();
		it != m_inspector->m_thread_manager->m_threadtable.end();
		++it)
	{
		sinsp_threadinfo* tinfo = &it->second;

		if(tinfo->is_main_thread())
		{
			blprogram np;

			//
			// Copy the basic thread info
			//
			np.m_comm = tinfo->m_comm;
			np.m_exe = tinfo->m_exe;
			//np.m_args = tinfo->m_args;
			//np.m_env = tinfo->m_env;
			np.m_container_id = tinfo->m_container_id;
			np.m_user_id = tinfo->m_uid;
			np.m_comm = tinfo->m_comm;

			//
			// Process the FD table
			//
			sinsp_fdtable* fdt = tinfo->get_fd_table();

			if(fdt != NULL)
			{
				for(auto itf : fdt->m_table)
				{
					sinsp_fdinfo_t* fdinfo = &itf.second;

					switch(fdinfo->m_type)
					{
					case SCAP_FD_FILE:
					{
						//
						// Add the entry to the file table
						//
						np.m_files.add(fdinfo->m_name, fdinfo->m_openflags, true);

						//
						// Add the entry to the directory table
						//
						np.m_dirs.add_dir(fdinfo->m_name, fdinfo->m_openflags, true);

						break;
					}
					case SCAP_FD_DIRECTORY:
						//
						// Add the entry to the directory table
						//
						np.m_dirs.add(fdinfo->m_name, fdinfo->m_openflags, true);

						break;
					case SCAP_FD_IPV4_SOCK:
						{
							ipv4tuple tuple = fdinfo->m_sockinfo.m_ipv4info;
							if(m_ifaddr_list->is_ipv4addr_in_local_machine(tuple.m_fields.m_dip, tinfo))
							{
								if(tuple.m_fields.m_l4proto == SCAP_L4_TCP)
								{
									np.m_server_ports.add_l_tcp(tuple.m_fields.m_dport);
									np.m_ip_endpoints.add_c_tcp(tuple.m_fields.m_sip);
									np.m_c_subnet_endpoints.add_c_tcp(
										bl_ip_endpoint_table::c_subnet(tuple.m_fields.m_sip));
								}
								else if(tuple.m_fields.m_l4proto == SCAP_L4_UDP)
								{
									np.m_server_ports.add_l_udp(tuple.m_fields.m_dport);
									np.m_ip_endpoints.add_udp(tuple.m_fields.m_sip);
									np.m_c_subnet_endpoints.add_udp(
										bl_ip_endpoint_table::c_subnet(tuple.m_fields.m_sip));
								}
							}
							else
							{
								if(tuple.m_fields.m_l4proto == SCAP_L4_TCP)
								{
									np.m_server_ports.add_r_tcp(tuple.m_fields.m_dport);
									np.m_ip_endpoints.add_s_tcp(tuple.m_fields.m_dip);
									np.m_c_subnet_endpoints.add_s_tcp(
										bl_ip_endpoint_table::c_subnet(tuple.m_fields.m_dip));
								}
								else if(tuple.m_fields.m_l4proto == SCAP_L4_UDP)
								{
									np.m_server_ports.add_r_udp(tuple.m_fields.m_dport);
									np.m_ip_endpoints.add_udp(tuple.m_fields.m_dip);
									np.m_c_subnet_endpoints.add_udp(
										bl_ip_endpoint_table::c_subnet(tuple.m_fields.m_dip));
								}
							}
						}
						break;
					case SCAP_FD_IPV4_SERVSOCK:
					{
						if(fdinfo->m_sockinfo.m_ipv4serverinfo.m_l4proto == SCAP_L4_TCP)
						{
							np.m_bound_ports.add_l_tcp(fdinfo->m_sockinfo.m_ipv4serverinfo.m_port);
						}
						else
						{
							np.m_bound_ports.add_l_udp(fdinfo->m_sockinfo.m_ipv4serverinfo.m_port);
						}
						break;
					}
					case SCAP_FD_IPV6_SERVSOCK:
					case SCAP_FD_IPV6_SOCK:
						break;
					default:
						break;
					}
				}
			}

			m_progtable[tinfo->m_program_hash] = np;
		}
	}
}

void sisnp_baseliner::init_containers()
{
	//
	// Go through the thread list and identify the main threads
	//
	m_container_table = *(m_inspector->m_container_manager.get_containers());
}

void sisnp_baseliner::register_callbacks(sinsp_fd_listener* listener)
{
	//
	// Initialize the FD listener
	//
	m_inspector->m_parser->m_fd_listener = listener;
}

void sisnp_baseliner::serialize_json(string filename)
{
	Json::Value root;
	Json::Value econt;
	Json::Value table(Json::arrayValue);
	Json::Value ctable;

	std::ofstream ofs(filename, std::ofstream::out);
	if(!ofs.is_open())
	{
		throw(sinsp_exception("can't open file " + filename + " for writing"));
	}

	for(auto& it : m_progtable)
	{
		Json::Value eprog;

		eprog["comm"] = it.second.m_comm;
		eprog["exe"] = it.second.m_exe;
		eprog["user_id"] = it.second.m_user_id;

		if(!it.second.m_container_id.empty())
		{
			eprog["container_id"] = it.second.m_container_id;
		}

/*
		// Args
		if(it.second.m_args.size() != 0)
		{
			Json::Value echild;

			for(auto it1 : it.second.m_args)
			{
				echild.append(it1);
			}

			eprog["args"] = echild;
		}

		// Env
		if(it.second.m_env.size() != 0)
		{
			Json::Value echild;

			for(auto it1 : it.second.m_env)
			{
				echild.append(it1);
			}

			eprog["env"] = echild;
		}
*/
		// Files
		Json::Value efiles;
		it.second.m_files.serialize_json(efiles);
		if(!efiles.empty())
		{
			eprog["files"] = efiles;
		}

		// Dirs
		Json::Value edirs;
		it.second.m_dirs.serialize_json(edirs);
		if(!edirs.empty())
		{
			eprog["dirs"] = edirs;
		}

		// Executed Programs
		Json::Value eeprogs;
		it.second.m_executed_programs.serialize_json(eeprogs);
		if(!eeprogs.empty())
		{
			eprog["executed_programs"] = eeprogs;
		}

		// Server ports
		Json::Value eserver_ports;
		it.second.m_server_ports.serialize_json(eserver_ports);
		if(!eserver_ports.empty())
		{
			eprog["server_ports"] = eserver_ports;
		}

		// bound ports
		Json::Value ebound_ports;
		it.second.m_bound_ports.serialize_json(ebound_ports);
		if(!ebound_ports.empty())
		{
			eprog["bound_ports"] = ebound_ports;
		}

		// IP endpoints
		Json::Value eip_endpoints;
		it.second.m_ip_endpoints.serialize_json(eip_endpoints);
		if(!eip_endpoints.empty())
		{
			eprog["ip_endpoints"] = eip_endpoints;
		}

		// IP c subnets
		Json::Value ec_subnet_endpoints;
		it.second.m_c_subnet_endpoints.serialize_json(ec_subnet_endpoints);
		if(!ec_subnet_endpoints.empty())
		{
			eprog["c_subnet_endpoints"] = ec_subnet_endpoints;
		}

		table.append(eprog);
	}

	for(auto& it : m_container_table)
	{
		Json::Value cinfo;
		cinfo["image"] = it.second.m_image;
		cinfo["name"] = it.second.m_name;

		ctable[it.second.m_id] = cinfo;
	}

	root["progs"] = table;
	root["containers"] = ctable;

	root["machine"]["hostname"] = m_hostname;
	root["machine"]["hostid"] = to_string(m_hostid);

	ofs << root << std::endl;
}

void sisnp_baseliner::serialize_protobuf(draiosproto::falco_baseline* pbentry)
{
	for(auto& it : m_progtable)
	{
		draiosproto::falco_prog* prog = pbentry->add_progs();
		prog->set_comm(it.second.m_comm);
		prog->set_exe(it.second.m_exe);
		prog->set_user_id(it.second.m_user_id);
		if(!it.second.m_container_id.empty())
		{
			prog->set_container_id(it.second.m_container_id);
		}

		// Files
		draiosproto::falco_category* cfiles = prog->add_cats();
		cfiles->set_name("files");
		it.second.m_files.serialize_protobuf(cfiles);

		// Dirs
		draiosproto::falco_category* cdirs = prog->add_cats();
		cdirs->set_name("dirs");
		it.second.m_dirs.serialize_protobuf(cdirs);

		// Executed Programs
		draiosproto::falco_category* cexecuted_programs = prog->add_cats();
		cexecuted_programs->set_name("executed_programs");
		it.second.m_executed_programs.serialize_protobuf(cexecuted_programs);

		// Server ports
		draiosproto::falco_category* cserver_ports = prog->add_cats();
		cserver_ports->set_name("server_ports");
		it.second.m_server_ports.serialize_protobuf(cserver_ports);

		// bound ports
		draiosproto::falco_category* cbound_ports = prog->add_cats();
		cbound_ports->set_name("bound_ports");
		it.second.m_bound_ports.serialize_protobuf(cbound_ports);

		// IP endpoints
		draiosproto::falco_category* cip_endpoints = prog->add_cats();
		cip_endpoints->set_name("ip_endpoints");
		it.second.m_ip_endpoints.serialize_protobuf(cip_endpoints);

		// IP c subnets
		draiosproto::falco_category* cc_subnet_endpoints = prog->add_cats();
		cc_subnet_endpoints->set_name("c_subnet_endpoints");
		it.second.m_c_subnet_endpoints.serialize_protobuf(cc_subnet_endpoints);
	}
}

void sisnp_baseliner::emit_as_json(uint64_t time)
{	
	serialize_json(string("bline/") + to_string(m_hostid) + "_" + to_string(time) + ".json");

	clear_tables();
	load_tables();
}

void sisnp_baseliner::emit_as_protobuf(draiosproto::falco_baseline* pbentry)
{

	serialize_protobuf(pbentry);

	clear_tables();
	load_tables();
}

void sisnp_baseliner::on_file_open(sinsp_evt *evt, string& name, uint32_t openflags)
{
	sinsp_threadinfo* tinfo = evt->get_thread_info();

	//
	// Find the program entry
	//
	auto it = m_progtable.find(tinfo->m_program_hash);

	if(it == m_progtable.end())
	{
		ASSERT(false);
		return;
	}

	blprogram& pinfo = it->second;

	pinfo.m_files.add(name, openflags, false);

	//
	// Add the entry to the directory table
	//
	pinfo.m_dirs.add_dir(name, openflags, false);
}

void sisnp_baseliner::on_new_proc(sinsp_threadinfo* tinfo)
{
	ASSERT(tinfo != NULL);
	size_t phash = tinfo->m_program_hash;

	//
	// Find the program entry
	//
	auto it = m_progtable.find(phash);

	if(it == m_progtable.end())
	{
		pair<unordered_map<size_t, blprogram>::iterator, bool> insert_res = 
			m_progtable.emplace(phash, tinfo->m_comm);

		insert_res.first->second.m_comm = tinfo->m_comm;
		insert_res.first->second.m_exe = tinfo->m_exe;
		//insert_res.first->second.m_args = tinfo->m_args;
		//insert_res.first->second.m_parent_comm = tinfo->m_comm;
		//insert_res.first->second.m_env = tinfo->m_env;
		insert_res.first->second.m_container_id = tinfo->m_container_id;
		insert_res.first->second.m_user_id = tinfo->m_uid;

		sinsp_threadinfo* ptinfo = m_inspector->get_thread(tinfo->m_ptid);

		if(ptinfo != NULL)
		{
			auto itp = m_progtable.find(ptinfo->m_program_hash);

			if(itp != m_progtable.end())
			{
				itp->second.m_executed_programs.add(tinfo->m_exe);
			}
		}
	}
	else
	{
#ifdef _DEBUG
		blprogram& pinfo = it->second;
#endif
		//ASSERT(pinfo.m_comm == tinfo->m_comm);
		ASSERT(pinfo.m_exe == tinfo->m_exe);
		//ASSERT(pinfo.m_args == tinfo->m_args);
		//ASSERT(pinfo.m_parent_comm == tinfo->m_parent_comm);
		ASSERT(pinfo.m_container_id == tinfo->m_container_id);
		//ASSERT(pinfo.m_user_id == tinfo->m_uid);
	}
}

void sisnp_baseliner::on_connect(sinsp_evt *evt)
{
	//
	// Note: the presence of fdinfo is assured in sinsp_parser::parse_connect_exit, so
	//       we don't need to check it
	//
	sinsp_fdinfo_t* fdinfo = evt->get_fd_info();

	if(fdinfo->m_type == SCAP_FD_IPV4_SOCK)
	{
		sinsp_threadinfo* tinfo = evt->get_thread_info();

		//
		// Find the program entry
		//
		auto it = m_progtable.find(tinfo->m_program_hash);

		if(it == m_progtable.end())
		{
			ASSERT(false);
			return;
		}

		blprogram& pinfo = it->second;

		ipv4tuple tuple = fdinfo->m_sockinfo.m_ipv4info;

		if(tuple.m_fields.m_l4proto == SCAP_L4_TCP)
		{
			pinfo.m_server_ports.add_r_tcp(tuple.m_fields.m_dport);
			pinfo.m_ip_endpoints.add_s_tcp(tuple.m_fields.m_dip);
			pinfo.m_c_subnet_endpoints.add_s_tcp(
				bl_ip_endpoint_table::c_subnet(tuple.m_fields.m_dip));
		}
		else
		{
			ASSERT(tuple.m_fields.m_l4proto == SCAP_L4_UDP);
			pinfo.m_server_ports.add_r_udp(tuple.m_fields.m_dport);
			pinfo.m_ip_endpoints.add_udp(tuple.m_fields.m_dip);
			pinfo.m_c_subnet_endpoints.add_udp(
				bl_ip_endpoint_table::c_subnet(tuple.m_fields.m_dip));
		}
	}
}

void sisnp_baseliner::on_accept(sinsp_evt *evt, sinsp_fdinfo_t* fdinfo)
{
	if(fdinfo->m_type == SCAP_FD_IPV4_SOCK)
	{
		sinsp_threadinfo* tinfo = evt->get_thread_info();

		//
		// Find the program entry
		//
		auto it = m_progtable.find(tinfo->m_program_hash);

		if(it == m_progtable.end())
		{
			ASSERT(false);
			return;
		}

		blprogram& pinfo = it->second;

		ipv4tuple tuple = fdinfo->m_sockinfo.m_ipv4info;
		pinfo.m_server_ports.add_l_tcp(tuple.m_fields.m_dport);
		pinfo.m_ip_endpoints.add_c_tcp(tuple.m_fields.m_sip);
		pinfo.m_c_subnet_endpoints.add_c_tcp(
			bl_ip_endpoint_table::c_subnet(tuple.m_fields.m_sip));
	}
}

void sisnp_baseliner::on_bind(sinsp_evt *evt)
{
	//
	// Note: the presence of fdinfo is assured in sinsp_parser::parse_connect_exit, so
	//       we don't need to check it
	//
	sinsp_fdinfo_t* fdinfo = evt->get_fd_info();
	ipv4serverinfo tuple = fdinfo->m_sockinfo.m_ipv4serverinfo;

	if(tuple.m_l4proto == SCAP_L4_TCP &&
		fdinfo->m_type == SCAP_FD_IPV4_SOCK)
	{
ASSERT(false); // Remove this assertion when this code is tested and validated
		sinsp_threadinfo* tinfo = evt->get_thread_info();

		//
		// Find the program entry
		//
		auto it = m_progtable.find(tinfo->m_program_hash);

		if(it == m_progtable.end())
		{
			ASSERT(false);
			return;
		}

		blprogram& pinfo = it->second;

		pinfo.m_bound_ports.add_l_tcp(tuple.m_port);
	}
}

void sisnp_baseliner::on_new_container(const sinsp_container_info& container_info)
{
	m_container_table[container_info.m_id] = container_info;
}