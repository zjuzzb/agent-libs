#pragma once

#include "type_config.h"

// suppress depreacated warnings for auto_ptr in boost
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <yaml-cpp/yaml.h>
#pragma GCC diagnostic pop

enum class k8s_export_format
{
	DEDICATED,
	GENERIC
};


extern type_config<k8s_export_format> c_new_k8s_global_export_format;
extern type_config<k8s_export_format> c_new_k8s_local_export_format;
