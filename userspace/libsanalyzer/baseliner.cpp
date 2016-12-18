#include <iostream>
#include <sinsp.h>
#include <sinsp_int.h>
#include "utils.h"
#ifdef HAS_ANALYZER
#include "draios.pb.h"
#include "analyzer_int.h"
#include "analyzer.h"
#endif
#include <baseliner.h>

extern sinsp_evttables g_infotables;

///////////////////////////////////////////////////////////////////////////////
// sisnp_baseliner implementation
///////////////////////////////////////////////////////////////////////////////
void sisnp_baseliner::init(sinsp* inspector)
{
	m_inspector = inspector;
	m_ifaddr_list = m_inspector->get_ifaddr_list();
	load_tables(0);
#ifndef HAS_ANALYZER
	const scap_machine_info* minfo = m_inspector->get_machine_info();
	m_hostname = minfo->hostname;
	m_hostid = 12345;	// XXX implement this
#endif
}

void sisnp_baseliner::load_tables(uint64_t time)
{
	init_containers();
	init_programs(time);
}

void sisnp_baseliner::clear_tables()
{
	m_progtable.clear();
	m_container_table.clear();
}

void sisnp_baseliner::init_programs(uint64_t time)
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
			if(tinfo->m_comm == "java")
			{
				np.m_pids.push_back(tinfo->m_pid);
			}
			//np.m_args = tinfo->m_args;
			//np.m_env = tinfo->m_env;
			np.m_container_id = tinfo->m_container_id;
			np.m_user_id = tinfo->m_uid;
			np.m_comm = tinfo->m_comm;

			//
			// Calculate the delta from program creation.
			// Note: we don't search for the main process thread because this loop already makes 
			//       sure to go through main threads only.
			//
			uint64_t cdelta = 0;

			if(time != 0)
			{
				uint64_t clone_ts = (tinfo->m_clone_ts != 0)? tinfo->m_clone_ts : m_inspector->m_firstevent_ts;
				cdelta = time - clone_ts;
			}

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
						np.m_files.add(fdinfo->m_name, fdinfo->m_openflags, true, cdelta);

						//
						// Add the entry to the directory tables
						//
						string sdir = blfiletable::file_to_dir(fdinfo->m_name);
						np.m_dirs.add(sdir, fdinfo->m_openflags, true, cdelta);
//						np.m_dirs_reduced.add(sdir, fdinfo->m_openflags, true, cdelta);

						break;
					}
					case SCAP_FD_DIRECTORY:
					{
						//
						// Add the entry to the directory tables
						//
						string sdir = fdinfo->m_name + '/';
						np.m_dirs.add(sdir, fdinfo->m_openflags, true, cdelta);
//						np.m_dirs_reduced.add(sdir, fdinfo->m_openflags, true, cdelta);

						break;
					}
					case SCAP_FD_IPV4_SOCK:
						{
							ipv4tuple tuple = fdinfo->m_sockinfo.m_ipv4info;

							if(fdinfo->is_role_server())
							{
								if(tuple.m_fields.m_l4proto == SCAP_L4_TCP)
								{
									np.m_server_ports.add_l_tcp(tuple.m_fields.m_dport, cdelta);
									np.m_ip_endpoints.add_c_tcp(tuple.m_fields.m_sip, cdelta);
									np.m_c_subnet_endpoints.add_c_tcp(
										bl_ip_endpoint_table::c_subnet(tuple.m_fields.m_sip), cdelta);
								}
								else if(tuple.m_fields.m_l4proto == SCAP_L4_UDP)
								{
									np.m_server_ports.add_l_udp(tuple.m_fields.m_dport, cdelta);
									np.m_ip_endpoints.add_udp(tuple.m_fields.m_sip, cdelta);
									np.m_c_subnet_endpoints.add_udp(
										bl_ip_endpoint_table::c_subnet(tuple.m_fields.m_sip), cdelta);
								}
							}
							else
							{
								if(tuple.m_fields.m_l4proto == SCAP_L4_TCP)
								{
									np.m_server_ports.add_r_tcp(tuple.m_fields.m_dport, cdelta);
									np.m_ip_endpoints.add_s_tcp(tuple.m_fields.m_dip, cdelta);
									np.m_c_subnet_endpoints.add_s_tcp(
										bl_ip_endpoint_table::c_subnet(tuple.m_fields.m_dip), cdelta);
								}
								else if(tuple.m_fields.m_l4proto == SCAP_L4_UDP)
								{
									np.m_server_ports.add_r_udp(tuple.m_fields.m_dport, cdelta);
									np.m_ip_endpoints.add_udp(tuple.m_fields.m_dip, cdelta);
									np.m_c_subnet_endpoints.add_udp(
										bl_ip_endpoint_table::c_subnet(tuple.m_fields.m_dip), cdelta);
								}
							}
						}
						break;
					case SCAP_FD_IPV4_SERVSOCK:
					{
						if(fdinfo->m_sockinfo.m_ipv4serverinfo.m_l4proto == SCAP_L4_TCP)
						{
							np.m_bound_ports.add_l_tcp(fdinfo->m_sockinfo.m_ipv4serverinfo.m_port, cdelta);
						}
						if(fdinfo->m_sockinfo.m_ipv4serverinfo.m_l4proto == SCAP_L4_UDP)
						{
							np.m_bound_ports.add_l_udp(fdinfo->m_sockinfo.m_ipv4serverinfo.m_port, cdelta);
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

			if(m_progtable.size() >= BL_MAX_PROG_TABLE_SIZE)
			{
				return;
			}

			m_progtable[tinfo->m_program_hash_falco] = np;
			m_progtable[tinfo->m_program_hash_falco].m_dirs.m_regular_table.m_max_table_size = BL_MAX_DIRS_TABLE_SIZE;
			m_progtable[tinfo->m_program_hash_falco].m_dirs.m_startup_table.m_max_table_size = BL_MAX_DIRS_TABLE_SIZE;
		}
	}

	//
	// In this second pass, we go over the thread table and add all of the main processes
	// to their prarents' executed program list
	//
	for(auto it = m_inspector->m_thread_manager->m_threadtable.begin();
		it != m_inspector->m_thread_manager->m_threadtable.end();
		++it)
	{
		sinsp_threadinfo* tinfo = &it->second;

		if(tinfo->is_main_thread())
		{
			auto ptinfo = tinfo->get_parent_thread();
			if(ptinfo == NULL)
			{
				continue;
			}

			auto itp = m_progtable.find(ptinfo->m_program_hash_falco);

			if(itp != m_progtable.end())
			{
				uint64_t cdelta = 0;
				uint64_t clone_ts;

				if(time != 0)
				{
					clone_ts = (tinfo->m_clone_ts != 0)? tinfo->m_clone_ts : m_inspector->m_firstevent_ts;
					cdelta = time - clone_ts;
				}

				itp->second.m_executed_programs.add(tinfo->m_comm, cdelta);
			}
		}
	}

}

void sisnp_baseliner::init_containers()
{
	const unordered_map<string, sinsp_container_info>* containers = m_inspector->m_container_manager.get_containers();

	for(auto& it : *containers)
	{
		m_container_table[it.first] = blcontainer(it.second.m_name, 
			it.second.m_image, it.second.m_imageid);
	}
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

		// Dirs reduced
		//Json::Value edirsr;
		//it.second.m_dirs_reduced.serialize_json(edirsr);
		//if(!edirsr.empty())
		//{
		//	eprog["dirsr"] = edirsr;
		//}

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

	root["progs"] = table;
	
	for(auto& it : m_container_table)
	{
		Json::Value cinfo;
		cinfo["name"] = it.second.m_name;
		cinfo["image_name"] = it.second.m_image_name;
		cinfo["image_id"] = it.second.m_image_id;

		ctable[it.first] = cinfo;
	}

	root["containers"] = ctable;

#ifndef HAS_ANALYZER
	root["machine"]["hostname"] = m_hostname;
	root["machine"]["hostid"] = to_string(m_hostid);
#endif

	ofs << root << std::endl;
}

#ifdef HAS_ANALYZER
void sisnp_baseliner::serialize_protobuf(draiosproto::falco_baseline* pbentry)
{
	//
	// Serialize the programs
	//
	for(auto& it : m_progtable)
	{
		draiosproto::falco_prog* prog = pbentry->add_progs();

		prog->set_comm(it.second.m_comm);
		prog->set_exe(it.second.m_exe);

		//
		// For java processes, we patch the comm and exe with the name coming from
		// the JMX information for the first process associated with this program
		//
		if(it.second.m_comm == "java")
		{
			ASSERT(it.second.m_pids.size() != 0);

			if(it.second.m_pids.size() != 0)
			{
				auto el = m_inspector->m_analyzer->m_jmx_metrics.find(it.second.m_pids[0]);
				if(el != m_inspector->m_analyzer->m_jmx_metrics.end())
				{
					string jname = el->second.name();
					prog->set_comm(jname);
				}
			}
		}
		prog->set_user_id(it.second.m_user_id);
		if(!it.second.m_container_id.empty())
		{
			prog->set_container_id(it.second.m_container_id);
		}

		// Files
		if(it.second.m_files.has_data())
		{
			draiosproto::falco_category* cfiles = prog->add_cats();
			cfiles->set_name("files");
			it.second.m_files.serialize_protobuf(cfiles);
		}

		// Dirs
		if(it.second.m_dirs.has_data())
		{
			draiosproto::falco_category* cdirs = prog->add_cats();
			cdirs->set_name("dirs");
			it.second.m_dirs.serialize_protobuf(cdirs);
		}

		// Dirs reduced
		//if(it.second.m_dirs_reduced.has_data())
		//{
		//	draiosproto::falco_category* cdirs = prog->add_cats();
		//	cdirs->set_name("dirsr");
		//	it.second.m_dirs_reduced.serialize_protobuf(cdirs);
		//}

		// Executed Programs
		if(it.second.m_executed_programs.has_data())
		{
			draiosproto::falco_category* cexecuted_programs = prog->add_cats();
			cexecuted_programs->set_name("executed_programs");
			it.second.m_executed_programs.serialize_protobuf(cexecuted_programs);
		}

		// Server ports
		if(it.second.m_server_ports.has_data())
		{
			draiosproto::falco_category* cserver_ports = prog->add_cats();
			cserver_ports->set_name("server_ports");
			it.second.m_server_ports.serialize_protobuf(cserver_ports);
		}

		// bound ports
		if(it.second.m_bound_ports.has_data())
		{
			draiosproto::falco_category* cbound_ports = prog->add_cats();
			cbound_ports->set_name("bound_ports");
			it.second.m_bound_ports.serialize_protobuf(cbound_ports);
		}

		// IP endpoints
		if(it.second.m_ip_endpoints.has_data())
		{
			draiosproto::falco_category* cip_endpoints = prog->add_cats();
			cip_endpoints->set_name("ip_endpoints");
			it.second.m_ip_endpoints.serialize_protobuf(cip_endpoints);
		}

		// IP c subnets
		if(it.second.m_c_subnet_endpoints.has_data())
		{
			draiosproto::falco_category* cc_subnet_endpoints = prog->add_cats();
			cc_subnet_endpoints->set_name("c_subnet_endpoints");
			it.second.m_c_subnet_endpoints.serialize_protobuf(cc_subnet_endpoints);
		}
	}

	//
	// Serialize the containers
	//
	for (auto& it : m_container_table)
	{
		draiosproto::falco_container* cont = pbentry->add_containers();

		cont->set_id(it.first);
		cont->set_name(it.second.m_name);

		if (it.second.m_image_name != "")
		{
			cont->set_image_name(it.second.m_image_name);
		}

		if (it.second.m_image_id != "")
		{
			cont->set_image_id(it.second.m_image_id);
		}
	}
}
#endif

#ifndef HAS_ANALYZER
void sisnp_baseliner::emit_as_json(uint64_t time)
{	
	serialize_json(string("bline/") + to_string(m_hostid) + "_" + to_string(time) + ".json");

	clear_tables();
	load_tables(time);
}
#else
void sisnp_baseliner::emit_as_protobuf(uint64_t time, draiosproto::falco_baseline* pbentry)
{
	g_logger.format(sinsp_logger::SEV_INFO, "emitting falco baseline %" PRIu64, time);

	serialize_protobuf(pbentry);

	clear_tables();
	load_tables(time);
}
#endif

void sisnp_baseliner::on_file_open(sinsp_evt *evt, string& name, uint32_t openflags)
{
	sinsp_threadinfo* tinfo = evt->get_thread_info();

	//
	// Find the program entry
	//
	auto it = m_progtable.find(tinfo->m_program_hash_falco);

	if(it == m_progtable.end())
	{
		return;
	}

	blprogram& pinfo = it->second;

	sinsp_threadinfo* mt = tinfo->get_main_thread();
	uint64_t clone_ts;

	if(mt != NULL)
	{
		clone_ts = (mt->m_clone_ts != 0)? mt->m_clone_ts : m_inspector->m_firstevent_ts;
	}
	else
	{
		clone_ts = (tinfo->m_clone_ts != 0)? tinfo->m_clone_ts : m_inspector->m_firstevent_ts;
	}

	//
	// Add the entry to the file table
	//
	pinfo.m_files.add(name, openflags, false, 
		evt->get_ts() - clone_ts);

	//
	// Add the entry to the directory tables
	//
	string sdir = blfiletable::file_to_dir(name);

	pinfo.m_dirs.add(sdir, openflags, false,
		evt->get_ts() - clone_ts);

//	pinfo.m_dirs_reduced.add(sdir, openflags, false,
//		evt->get_ts() - clone_ts);
}

void sisnp_baseliner::on_new_proc(sinsp_evt *evt, sinsp_threadinfo* tinfo)
{
	ASSERT(tinfo != NULL);

	//
	// Note: the hash is exe+container
	//
	size_t phash = tinfo->m_program_hash_falco;

	//
	// Find the program entry
	//
	auto it = m_progtable.find(phash);

///////////////////////////////////////////////////////////////////////////////
// XXX Remove this
///////////////////////////////////////////////////////////////////////////////
if(tinfo->m_comm == "du" || tinfo->m_comm == "nice")
{
	lo(sinsp_logger::SEV_ERROR, "*detected execution of %s", tinfo->m_comm.c_str());
	lo(sinsp_logger::SEV_ERROR, "*exe=%s", tinfo->m_exe.c_str());
	for(auto a : tinfo->m_args)
	{
		lo(sinsp_logger::SEV_ERROR, "*a=%s", a.c_str());
	}
	lo(sinsp_logger::SEV_ERROR, "*container id=%s", tinfo->m_container_id.c_str());
}
///////////////////////////////////////////////////////////////////////////////
// XXX Remove this
///////////////////////////////////////////////////////////////////////////////

	if(it == m_progtable.end())
	{
		if(m_progtable.size() >= BL_MAX_PROG_TABLE_SIZE)
		{
			return;
		}

		blprogram np;

		np.m_comm = tinfo->m_comm;
		np.m_exe = tinfo->m_exe;
		np.m_container_id = tinfo->m_container_id;
		np.m_user_id = tinfo->m_uid;
		np.m_dirs.m_regular_table.m_max_table_size = BL_MAX_DIRS_TABLE_SIZE;
		np.m_dirs.m_startup_table.m_max_table_size = BL_MAX_DIRS_TABLE_SIZE;

///////////////////////////////////////////////////////////////////////////////
// XXX Remove this
///////////////////////////////////////////////////////////////////////////////
if(np.m_comm == "du" || np.m_comm == "nice")
{
	lo(sinsp_logger::SEV_ERROR, "!detected execution of %s", np.m_comm.c_str());
	lo(sinsp_logger::SEV_ERROR, "*container id=%s", np.m_container_id.c_str());
}
///////////////////////////////////////////////////////////////////////////////
// XXX Remove this
///////////////////////////////////////////////////////////////////////////////
		m_progtable[phash] = np;

		sinsp_threadinfo* ptinfo = m_inspector->get_thread(tinfo->m_ptid);

		if(ptinfo != NULL)
		{
			auto itp = m_progtable.find(ptinfo->m_program_hash_falco);

			if(itp != m_progtable.end())
			{
				sinsp_threadinfo* mt = tinfo->get_main_thread();
				uint64_t clone_ts;

				if(mt != NULL)
				{
					clone_ts = (mt->m_clone_ts != 0)? mt->m_clone_ts : m_inspector->m_firstevent_ts;
				}
				else
				{
					clone_ts = (tinfo->m_clone_ts != 0)? tinfo->m_clone_ts : m_inspector->m_firstevent_ts;
				}

				itp->second.m_executed_programs.add(tinfo->m_comm,
					evt->get_ts() - clone_ts);
			}
		}
	}
	else
	{
		blprogram& pinfo = it->second;
		if(tinfo->m_comm == "java" && tinfo->is_main_thread())
		{
			pinfo.m_pids.push_back(tinfo->m_pid);
		}

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
		auto it = m_progtable.find(tinfo->m_program_hash_falco);

		if(it == m_progtable.end())
		{
			return;
		}

		blprogram& pinfo = it->second;

		sinsp_threadinfo* mt = tinfo->get_main_thread();
		uint64_t clone_ts;

		if(mt != NULL)
		{
			clone_ts = (mt->m_clone_ts != 0)? mt->m_clone_ts : m_inspector->m_firstevent_ts;
		}
		else
		{
			clone_ts = (tinfo->m_clone_ts != 0)? tinfo->m_clone_ts : m_inspector->m_firstevent_ts;
		}

		uint64_t cdelta = evt->get_ts() - clone_ts;

		ipv4tuple tuple = fdinfo->m_sockinfo.m_ipv4info;

		if(tuple.m_fields.m_l4proto == SCAP_L4_TCP)
		{
			pinfo.m_server_ports.add_r_tcp(tuple.m_fields.m_dport, 
				cdelta);
			pinfo.m_ip_endpoints.add_s_tcp(tuple.m_fields.m_dip,
				cdelta);
			pinfo.m_c_subnet_endpoints.add_s_tcp(
				bl_ip_endpoint_table::c_subnet(tuple.m_fields.m_dip),
				cdelta);
		}
		else if(tuple.m_fields.m_l4proto == SCAP_L4_UDP)
		{
			pinfo.m_server_ports.add_r_udp(tuple.m_fields.m_dport,
				cdelta);
			pinfo.m_ip_endpoints.add_udp(tuple.m_fields.m_dip,
				cdelta);
			pinfo.m_c_subnet_endpoints.add_udp(
				bl_ip_endpoint_table::c_subnet(tuple.m_fields.m_dip),
				cdelta);
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
		auto it = m_progtable.find(tinfo->m_program_hash_falco);

		if(it == m_progtable.end())
		{
			return;
		}

		blprogram& pinfo = it->second;

		sinsp_threadinfo* mt = tinfo->get_main_thread();
		uint64_t clone_ts;

		if(mt != NULL)
		{
			clone_ts = (mt->m_clone_ts != 0)? mt->m_clone_ts : m_inspector->m_firstevent_ts;
		}
		else
		{
			clone_ts = (tinfo->m_clone_ts != 0)? tinfo->m_clone_ts : m_inspector->m_firstevent_ts;
		}

		uint64_t cdelta = evt->get_ts() - clone_ts;

		ipv4tuple tuple = fdinfo->m_sockinfo.m_ipv4info;
		pinfo.m_server_ports.add_l_tcp(tuple.m_fields.m_dport,
			cdelta);
		pinfo.m_ip_endpoints.add_c_tcp(tuple.m_fields.m_sip,
			cdelta);
		pinfo.m_c_subnet_endpoints.add_c_tcp(
			bl_ip_endpoint_table::c_subnet(tuple.m_fields.m_sip),
			cdelta);
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
		auto it = m_progtable.find(tinfo->m_program_hash_falco);

		if(it == m_progtable.end())
		{
			return;
		}

		blprogram& pinfo = it->second;

		sinsp_threadinfo* mt = tinfo->get_main_thread();
		uint64_t clone_ts;

		if(mt != NULL)
		{
			clone_ts = (mt->m_clone_ts != 0)? mt->m_clone_ts : m_inspector->m_firstevent_ts;
		}
		else
		{
			clone_ts = (tinfo->m_clone_ts != 0)? tinfo->m_clone_ts : m_inspector->m_firstevent_ts;
		}

		pinfo.m_bound_ports.add_l_tcp(tuple.m_port,
				evt->get_ts() - clone_ts);
	}
}

void sisnp_baseliner::on_new_container(const sinsp_container_info& container_info)
{
	m_container_table[container_info.m_id] = blcontainer(container_info.m_name, 
		container_info.m_image, 
		container_info.m_imageid);
}

#if 0
void sisnp_baseliner::process_event(sinsp_evt *evt)
{
	sinsp_threadinfo* tinfo = evt->get_thread_info();

	//
	// Find the program entry
	//
	auto it = m_progtable.find(tinfo->m_program_hash_falco);

	if(it == m_progtable.end())
	{
		return;
	}

	//
	//
	//
	uint16_t etype = evt->m_pevt->type;
	enum ppm_event_flags flags = g_infotables.m_event_info[etype].flags;

	if(etype == PPME_SCHEDSWITCH_6_E ||
		(flags & EC_INTERNAL) || (flags & EF_SKIPPARSERESET))
	{
		return NULL;
	}

	if(etype == PPME_GENERIC_E || etype == PPME_GENERIC_X)
	{
		sinsp_evt_param *parinfo = evt->get_param(0);
		ASSERT(parinfo->m_len == sizeof(uint16_t));
		uint16_t evid = *(uint16_t *)parinfo->m_val;

		evname = (uint8_t*)g_infotables.m_syscall_info_table[evid].name;
	}
	else
	{
		evname = (uint8_t*)evt->get_name();
	}

	return evname;
}
#endif
