#include <stdio.h>
#include <stdlib.h>
#include <algorithm>

#include "sinsp.h"
#include "sinsp_int.h"
#include "procparser.h"

sinsp_procparser::sinsp_procparser()
{
//	m_last_read_time = 0;
}

//
// See http://stackoverflow.com/questions/3017162/how-to-get-total-cpu-usage-in-linux-c
//
void sinsp_procparser::get_cpus_load(OUT vector<uint32_t>* loads)
{
	char line[512];
	char tmps[32];
	uint32_t j;
	uint32_t old_array_size = m_old_total_jiffies.size();

	FILE* f = fopen("/proc/stat", "r");

	//
	// Consume the first line which is the global system summary
	//
	if(fgets(line, sizeof(line), f) == NULL)
	{
		ASSERT(false);
		return;
	}

	//
	// Consume the cpu lines
	//
	for(j = 0; fgets(line, sizeof(line), f) != NULL; j++)
	{
		uint64_t val1, val2, val3, val4, val5, val6, val7;
		uint64_t total_jiffies;
		uint64_t work_jiffies;
		uint64_t delta_total_jiffies;
		uint64_t delta_work_jiffies;
		string linestr(line);

		if(linestr.substr(0, sizeof("cpu") - 1) != "cpu")
		{
			break;
		}

		if(sscanf(line, "%s %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64,
			tmps,
			&val1,
			&val2,
			&val3,
			&val4,
			&val5,
			&val6,
			&val7) != 8)
		{
			ASSERT(false);
			break;
		}

		ASSERT(val1 != 0);
		ASSERT(val2 != 0);
		ASSERT(val3 != 0);
		ASSERT(val4 != 0);
		ASSERT(val5 != 0);
		ASSERT(val6 != 0);
		ASSERT(val7 != 0);

		total_jiffies = val1 + val2 + val3 + val4 + val5 + val6 + val7;
		work_jiffies = val1 + val2 + val3;

		if(old_array_size != 0)
		{
			delta_work_jiffies = work_jiffies - m_old_work_jiffies[j];
			delta_total_jiffies = total_jiffies - m_old_total_jiffies[j];

			uint32_t load = (uint32_t)(delta_work_jiffies * 100 / delta_total_jiffies);
printf("*%u\n", load);
			loads->push_back(load);
		}

//		printf("%s\n", line);
		m_old_total_jiffies[j] = total_jiffies;
		m_old_work_jiffies[j] = work_jiffies;
	}

	fclose(f);
}
