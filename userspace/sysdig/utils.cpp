#include <time.h>
#include <stdio.h>
#include <assert.h>
#include <sinsp.h>

#define ONE_SEC_IN_NS 1000000000

int32_t gmt2local(time_t t)
{
	register int dt, dir;
	register struct tm *gmt, *loc;
	struct tm sgmt;

	if(t == 0)
	{
		t = time(NULL);
	}

	gmt = &sgmt;
	*gmt = *gmtime(&t);
	loc = localtime(&t);

	dt = (loc->tm_hour - gmt->tm_hour) * 60 * 60 +
	    (loc->tm_min - gmt->tm_min) * 60;

	dir = loc->tm_year - gmt->tm_year;
	if (dir == 0)
		dir = loc->tm_yday - gmt->tm_yday;

	dt += dir * 24 * 60 * 60;

	return (dt);
}

void ts_to_string(uint64_t ts, OUT string* res, bool full)
{
	struct tm *tm;
	time_t Time;
	static unsigned b_sec;
	static unsigned b_usec;
	uint64_t sec = ts / ONE_SEC_IN_NS;
	uint64_t nsec = ts % ONE_SEC_IN_NS;
	int32_t thiszone = gmt2local(0);
	int s = (sec + thiszone) % 86400;
	char buf[256];

	if(full) 
	{
		Time = (sec + thiszone) - s;
		tm = gmtime (&Time);
		if(!tm)
		{
			sprintf(buf, "<NA>");
		}
		else
		{
			sprintf(buf, "%04d-%02d-%02d ",
				   tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday);
		}
	}

	sprintf(buf, "%02d:%02d:%02d.%09u ",
			s / 3600, (s % 3600) / 60, s % 60, (unsigned)nsec);

	*res = buf;
}
