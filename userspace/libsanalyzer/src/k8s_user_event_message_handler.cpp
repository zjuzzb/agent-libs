#ifndef CYGWING_AGENT
#include "k8s_user_event_message_handler.h"
#include "infrastructure_state.h"
#include "user_event_logger.h"

k8s_user_event_message_handler::k8s_user_event_message_handler(uint64_t refresh_interval,
	std::string install_prefix, infrastructure_state *infra_state)
	: m_coclient(std::move(install_prefix)),
	  m_subscribed(false),
	  m_connected(false),
	  m_event_limit_exceeded(false),
	  m_refresh_interval(refresh_interval),
	  m_connect_interval(default_connect_interval),
	  m_infra_state(infra_state)
{
	m_callback = [this] (bool successful, google::protobuf::Message *response_msg) {

		if(successful) {
			sdc_internal::k8s_user_event *evt = (sdc_internal::k8s_user_event *)response_msg;
			glogf(sinsp_logger::SEV_DEBUG, "k8s_user_event: Got k8s event message.");
			handle_event(evt, m_infra_state);
		} else {
			//
			// Error from cointerface, destroy the whole state and subscribe again
			//
			glogf(sinsp_logger::SEV_WARNING, "k8s_user_event: Error while receiving k8s event message. Reset and retry.");
			m_connected = false;
			reset_connection();
		}
	};

	// Name translation table copied from sysdig/userspace/libsinsp/k8s_component.cpp
	m_name_translation =
	{
		//
		// Event translations, based on:
		// https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/container/event.go
		// https://github.com/kubernetes/kubernetes/blob/master/pkg/controller/controller_utils.go
		// https://github.com/kubernetes/kubernetes/blob/master/pkg/controller/node/nodecontroller.go
		// https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/kubelet.go
		// https://github.com/kubernetes/kubernetes/blob/master/pkg/controller/daemon/controller.go
		// https://github.com/kubernetes/kubernetes/blob/master/pkg/controller/deployment/deployment_controller.go
		// https://github.com/kubernetes/kubernetes/blob/master/pkg/controller/deployment/util/deployment_util.go
		//

		//
		// Node
		//

		// Node Controller
		{ "TerminatedAllPods",     "Terminated All Pods"},
		{ "RegisteredNode",        "Node Registered"},
		{ "RemovingNode",          "Removing Node"},
		{ "DeletingNode",          "Deleting Node"},
		{ "DeletingAllPods",       "Deleting All Pods"},
		{ "TerminatingEvictedPod", "Terminating Evicted Pod" },

		// Kubelet
		{ "NodeReady",               "Node Ready"                 },
		{ "NodeNotReady",            "Node not Ready"             },
		{ "NodeSchedulable",         "Node is Schedulable"        },
		{ "NodeNotSchedulable",      "Node is not Schedulable"    },
		{ "CIDRNotAvailable",        "CIDR not Available"         },
		{ "CIDRAssignmentFailed",    "CIDR Assignment Failed"     },
		{ "Starting",                "Starting Kubelet"           },
		{ "KubeletSetupFailed",      "Kubelet Setup Failed"       },
		{ "FailedMount",             "Volume Mount Failed"        },
		{ "NodeSelectorMismatching", "Node Selector Mismatch"     },
		{ "InsufficientFreeCPU",     "Insufficient Free CPU"      },
		{ "InsufficientFreeMemory",  "Insufficient Free Memory"   },
		{ "OutOfDisk",               "Out of Disk"                },
		{ "HostNetworkNotSupported", "Host Network not Supported" },
		{ "NilShaper",               "Undefined Shaper"           },
		{ "Rebooted",                "Node Rebooted"              },
		{ "NodeHasSufficientDisk",   "Node Has Sufficient Disk"   },
		{ "NodeOutOfDisk",           "Node Out of Disk Space"     },

		// Image manager
		{ "InvalidDiskCapacity", "Invalid Disk Capacity"  },
		{ "FreeDiskSpaceFailed", "Free Disk Space Failed" },

		//
		// Pod
		//

		// Image
		{ "Pulling",           "Pulling Image"                                },
		{ "Pulled",            "Image Pulled"                                 },
		{ "Failed",            "Container Image Pull, Create or Start Failed" },
		{ "InspectFailed",     "Image Inspect Failed"                         },
		{ "ErrImageNeverPull", "Image NeverPull Policy Error"                 },
		{ "BackOff",           "Back Off Container Start or Image Pull"       },

		//{ "OutOfDisk" ,"Out of Disk" }, duplicate

		// Container
		{ "Created", "Container Created"                },
		{ "Started", "Container Started"                },
		//{ "Failed",  "Container Create or Start Failed" }, duplicate
		{ "Killing", "Killing Container"                },

		//{ "BackOff", "Backoff Start Container" }, duplicate

		// Probe
		{ "Unhealthy", "Container Unhealthy" },

		// Pod worker
		{ "FailedSync", "Pod Sync Failed" },

		// Config
		{ "FailedValidation", "Failed Configuration Validation" },
		{ "HostPortConflict", "Host/Port Conflict"              },

		//
		// Replication Controller
		//
		{ "SuccessfulCreate",  "Pod Created"      },
		{ "FailedCreate",      "Pod Create Failed"},
		{ "SuccessfulDelete",  "Pod Deleted"      },
		{ "FailedDelete",      "Pod Delete Failed"},

		//
		// Replica Set
		//
		// { "SuccessfulCreate",  "Pod Created"      }, duplicate
		// { "FailedCreate",      "Pod Create Failed"}, duplicate
		// { "SuccessfulDelete",  "Pod Deleted"      }, duplicate
		// { "FailedDelete",      "Pod Delete Failed"}  duplicate

		//
		// Deployment
		//
		{ "SelectingAll",                        "Selecting All Pods"       },
		{ "ScalingReplicaSet",                   "Scaling Replica Set"      },
		{ "DeploymentRollbackRevisionNotFound",  "No revision to roll back" },
		{ "DeploymentRollbackTemplateUnchanged", "Skipping Rollback"        },
		{ "DeploymentRollback",                  "Rollback Done"            }

		//
		// Daemon Set
		//
		// { "SelectingAll", "Selecting All Pods" } duplicate
	};
}

k8s_user_event_message_handler::~k8s_user_event_message_handler()
{
}

string k8s_user_event_message_handler::translate_name(const string &name) const
{
	const auto& translation = m_name_translation.find(name);
	if (translation != m_name_translation.end())
	{
		return translation->second;
	}

	// Return input name if no translation is found
	return name;
}

void k8s_user_event_message_handler::handle_event(sdc_internal::k8s_user_event *evt, infrastructure_state *infra_state)
{
	if (!m_event_filter)
	{
		glogf(sinsp_logger::SEV_DEBUG, "k8s_user_event: no filter found");
		return;
	}

	// this code is a bit hokey, but we do the check in two steps
	// 1) check if the filter allows everything
	// 2) if not, check if the filter allows our specific event type,
	//
	// If both checks fail we return prematurely
	bool allowed = m_event_filter->allows_all();
	if (!allowed && evt->has_obj() && !evt->obj().kind().empty()) {
		allowed = m_event_filter->allows_all(evt->obj().kind()) ||
			(!evt->reason().empty() &&
			m_event_filter->has(evt->obj().kind(), evt->reason()));
	}

	event_scope scope;
	sinsp_user_event::tag_map_t tags;
	if (!allowed)
	{
		glogf(sinsp_logger::SEV_DEBUG,
	      "k8s_user_event: no filter match for %s, %s", evt->obj().kind().c_str(), evt->reason().c_str());

		return;
	}

	if (get_user_event_count() >= EVENT_QUEUE_LIMIT)
	{
		if (!m_event_limit_exceeded)
		{
			sinsp_user_event::emit_event_overflow("Kubernetes", m_machine_id);
			m_event_limit_exceeded = true;
		}
		return;
	}

	m_event_limit_exceeded = false;

	glogf(sinsp_logger::SEV_DEBUG,
      "k8s_user_event: filter match for %s, %s", evt->obj().kind().c_str(), evt->reason().c_str());
	time_t ts = evt->last_timestamp();

	tags["source"] = "kubernetes";
	if ((ts != (time_t)-1) && (ts > (time_t)0))
	{
		if (evt->has_obj())
		{
			int scope_names = 0;
			// Construct scope based on names of object and parents as
			// stored in object tags in infrastructure_state
			// This should work in most cases
			if (!evt->obj().kind().empty() && !evt->obj().uid().empty() && infra_state)
			{
				// Translate kind to string as used in infra_state
				string kind = "k8s_" + evt->obj().kind();
				transform(kind.begin()+4, kind.end(), kind.begin()+4, ::tolower);
				auto uid = make_pair(kind, evt->obj().uid());
				scope_names = infra_state->get_scope_names(uid, &scope);

				string k8s_cluster_name = infra_state->get_k8s_cluster_name();
				if (!k8s_cluster_name.empty()) {
					scope.add("kubernetes.cluster.name", k8s_cluster_name);
					// Don't increment scope_names for cluster name because we
					// still need to fall back to legacy scope determination if
					// no other entities were found in the hierarchy.
				}

				glogf(sinsp_logger::SEV_DEBUG, "k8s_user_event: got %d scopes for %s:%s",
					scope_names, kind.c_str(), evt->obj().uid().c_str());
			}
			if (scope_names < 1)
			{
				glogf(sinsp_logger::SEV_DEBUG, "k8s_user_event: falling back to legacy scope for %s:%s",
					evt->obj().kind().c_str(), evt->obj().uid().c_str());
				// Didn't find scope through infra-state,
				// fall back to constructing scope the old way
				if (!evt->obj().namespace_().empty())
				{
					scope.add("kubernetes.namespace.name", evt->obj().namespace_());
				}
				if (!evt->obj().kind().empty() && !evt->obj().name().empty())
				{
					string kind = evt->obj().kind();
					// Only transform first character to lowercase: ReplicaSet -> replicaSet
					// I THINK this is because k8s_state parses the events this way (see k8s_event.cpp and
					// k8s_component.cpp). It is hideous.
					kind[0] = ::tolower(kind[0]);
					scope.add("kubernetes." + kind + ".name", evt->obj().name());
				}
			}
		}
		string name = translate_name(evt->reason());
		string message = evt->message();
		string logstr = sinsp_user_event::to_string(ts,
							    std::move(name),
							    std::move(message),
							    std::move(scope),
							    std::move(tags));
		glogf(sinsp_logger::SEV_DEBUG,
			"k8s_user_event: new event update: %s", logstr.c_str());

		// The specifial severities here are picked up by the glooger infrastructure and sent to the right queue
		user_event_logger::log(logstr, (evt->type() == "Warning") ? user_event_logger::SEV_EVT_WARNING : user_event_logger::SEV_EVT_INFORMATION);
	} else {
		glogf(sinsp_logger::SEV_INFO,
			"k8s_user_event: new event, bad timestamp %ld", evt->last_timestamp());
	}
}

void k8s_user_event_message_handler::reset_connection()
{
	if (m_subscribed) {
		connect();
	}
}

void k8s_user_event_message_handler::subscribe(uint64_t timeout_s, user_event_filter_t::ptr_t filter)
{
	ASSERT(!m_connected);
	m_event_filter = filter;

	glogf(sinsp_logger::SEV_INFO,
	      "k8s_user_event: Subscribe to k8s event messages, reconnect interval: %d sec",
	      timeout_s);
	m_connect_interval.interval(timeout_s * ONE_SECOND_IN_NS);

	connect();
}

void k8s_user_event_message_handler::connect(uint64_t ts)
{
	if (m_connected)
	{
		glogf(sinsp_logger::SEV_DEBUG,
		      "k8s_user_event: Ignoring k8s message connection attempt because an RPC is already active");
		return;
	}
	m_connect_interval.run(
		[this]()
		{
			glogf(sinsp_logger::SEV_INFO,
				"k8s_user_event: Connect to k8s event messages");
			sdc_internal::orchestrator_attach_user_events_stream_command cmd;
			m_subscribed = true;
			m_connected = true;
			m_coclient.get_orchestrator_event_messages(cmd, m_callback);
		}, ts);
}

void k8s_user_event_message_handler::refresh(uint64_t ts)
{
	if (!m_event_queue_set)
	{
		return;
	}

	if (m_connected) {
		ASSERT(m_subscribed);
		m_refresh_interval.run([this]()
		{
			m_coclient.process_queue();
		}, ts);
	} else if (m_subscribed) {
		connect(ts);
	}
}
#endif
