#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
using namespace google::protobuf::io;

#include "sinsp.h"
#include "sinsp_int.h"
#include "../../driver/ppm_ringbuffer.h"

#include "analyzer_int.h"
#include "metrics.h"
#undef min
#undef max
#include "draios.pb.h"
#include "analyzer_thread.h"
#include "percentile.h"

namespace {
std::shared_ptr<percentile> init_percentile(
	const std::set<double>* percentiles,
	std::shared_ptr<percentile> shared)
{
	if (shared) {
		return shared;
	} else if (percentiles && percentiles->size()) {
		return std::make_shared<percentile>(*percentiles);
	}
	return shared;
}

};

///////////////////////////////////////////////////////////////////////////////
// base sinsp_counter_percentile implementations
///////////////////////////////////////////////////////////////////////////////
sinsp_counter_percentile::sinsp_counter_percentile(
	const std::set<double>* percentiles,
	const sinsp_counter_percentile *shared)
	: m_serialize_pctl_data(false)
{
	m_percentile = init_percentile(percentiles, shared ? shared->m_percentile : nullptr);
}

void sinsp_counter_percentile::set_percentiles(
	const std::set<double>& percentiles,
	const sinsp_counter_percentile *shared)
{
	m_percentile = init_percentile(&percentiles, shared ? shared->m_percentile : nullptr);
}

void sinsp_counter_percentile::set_serialize_pctl_data(bool val)
{
	m_serialize_pctl_data = val;
}

sinsp_counter_percentile_in_out::sinsp_counter_percentile_in_out(
	const std::set<double>* percentiles,
	const sinsp_counter_percentile_in_out *shared)
	: m_serialize_pctl_data(false)
{
	m_percentile_in  = init_percentile(percentiles, shared ? shared->m_percentile_in  : nullptr);
	m_percentile_out = init_percentile(percentiles, shared ? shared->m_percentile_out : nullptr);
}

void sinsp_counter_percentile_in_out::set_percentiles(
	const std::set<double>& percentiles,
	const sinsp_counter_percentile_in_out *shared)
{
	m_percentile_in  = init_percentile(&percentiles,
	                                   shared ? shared->m_percentile_in  : nullptr);
	m_percentile_out = init_percentile(&percentiles,
	                                   shared ? shared->m_percentile_out : nullptr);
}

void sinsp_counter_percentile_in_out::set_serialize_pctl_data(bool val)
{
	m_serialize_pctl_data = val;
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_counter_time implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_counter_time::sinsp_counter_time(
	const std::set<double>* percentiles,
	const sinsp_counter_percentile *shared)
	: sinsp_counter_percentile(percentiles, shared)
{
	clear();
}

sinsp_counter_time::~sinsp_counter_time()
{
}

sinsp_counter_time::sinsp_counter_time(const sinsp_counter_time& other)
	: sinsp_counter_percentile()
	, m_count(other.m_count)
	, m_time_ns(other.m_time_ns)
{
	m_percentile.reset(other.m_percentile ? new percentile(*other.m_percentile) : nullptr);
}

sinsp_counter_time& sinsp_counter_time::operator=(sinsp_counter_time &other)
{
	if(this != &other)
	{
		m_count = other.m_count;
		m_time_ns = other.m_time_ns;
		if(other.m_percentile)
		{
			m_percentile = std::move(other.m_percentile);
		}
	}
	return *this;
}

void sinsp_counter_time::add(uint32_t cnt_delta, uint64_t time_delta)
{
	ASSERT(cnt_delta <= 1);

	m_count += cnt_delta;
	m_time_ns += time_delta;
	if(m_percentile)
	{
		m_percentile->add(time_delta);
	}
}

void sinsp_counter_time::add(sinsp_counter_time* other)
{
	m_count += other->m_count;
	m_time_ns += other->m_time_ns;
	// merge the 2 percentile stores if there are unique
	if(m_percentile && other->m_percentile &&
	   (m_percentile != other->m_percentile))
	{
		m_percentile->merge(other->m_percentile.get());
	}
}

void sinsp_counter_time::add(sinsp_counter_time_bytes* other)
{
	m_count += (other->m_count_in + other->m_count_out + other->m_count_other);
	m_time_ns += (other->m_time_ns_in + other->m_time_ns_out + other->m_time_ns_other);
	/*if(m_percentile && other->m_percentile)
	{
		m_percentile->merge(other->m_percentile.get());
	}*/
}

void sinsp_counter_time::add(sinsp_counter_time_bidirectional* other)
{
	m_count += (other->m_count_in + other->m_count_out + other->m_count_other);
	m_time_ns += (other->m_time_ns_in + other->m_time_ns_out + other->m_time_ns_other);
	if(m_percentile)
	{
		if(other->m_percentile_in)
		{
			m_percentile->merge(other->m_percentile_in.get());
		}
		if(other->m_percentile_out)
		{
			m_percentile->merge(other->m_percentile_out.get());
		}
	}
}

void sinsp_counter_time::clear()
{
	m_count = 0;
	m_time_ns = 0;
	if(m_percentile)
	{
		m_percentile->reset();
	}
}

void sinsp_counter_time::subtract(uint32_t cnt_delta, uint64_t time_delta)
{
	ASSERT(cnt_delta <= 1);

	if((cnt_delta > m_count) || (time_delta > m_time_ns))
	{
		ASSERT(false);
		m_count = 0;
		m_time_ns = 0;
		return;
	}

	m_count -= cnt_delta;
	m_time_ns -= time_delta;
}

void sinsp_counter_time::to_protobuf(draiosproto::counter_time* protobuf_msg, uint64_t tot_relevant_time_ns, uint32_t sampling_ratio)
{
	protobuf_msg->set_time_ns(m_time_ns * sampling_ratio);

	if(tot_relevant_time_ns != 0)
	{
		protobuf_msg->set_time_percentage((uint32_t)(((double)m_time_ns) * 10000 / (tot_relevant_time_ns * sampling_ratio)));
	}
	else
	{
		//
		// This can happen in case of gaps longer than 1 second in the event stream
		//
		protobuf_msg->set_time_percentage(0);
	}

	protobuf_msg->set_count(m_count * sampling_ratio);

	// percentiles
	typedef draiosproto::counter_time CTB;
	typedef draiosproto::counter_percentile CP;
	typedef draiosproto::counter_percentile_data CPD;
	if(m_percentile && m_percentile->sample_count())
	{
		m_percentile->to_protobuf<CTB, CP, CPD>(protobuf_msg,
		                                        &CTB::add_percentile,
		                                        (!m_serialize_pctl_data) ? nullptr :
		                                        &CTB::mutable_percentile_data);
	}
}

void sinsp_counter_time::coalesce_protobuf(draiosproto::counter_time* protobuf_msg,
					   uint64_t tot_relevant_time_ns,
					   uint64_t& denom,
					   const uint32_t sampling_ratio)
{
	protobuf_msg->set_time_ns(protobuf_msg->time_ns() + m_time_ns * sampling_ratio);

	if(tot_relevant_time_ns != 0)
	{
		uint64_t new_denom = denom + tot_relevant_time_ns * sampling_ratio;
		uint64_t prev_numer = denom * protobuf_msg->time_percentage();
		protobuf_msg->set_time_percentage((uint32_t)(prev_numer + (double)m_time_ns * 10000) / new_denom);
		denom = new_denom;
	}

	protobuf_msg->set_count(protobuf_msg->count() + m_count * sampling_ratio);
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_counter_time_bidirectional implementation
///////////////////////////////////////////////////////////////////////////////

sinsp_counter_time_bidirectional::sinsp_counter_time_bidirectional(
	const std::set<double>* percentiles,
	const sinsp_counter_percentile_in_out *shared)
	: sinsp_counter_percentile_in_out(percentiles, shared)
{
	clear();
}

sinsp_counter_time_bidirectional::~sinsp_counter_time_bidirectional()
{
}

sinsp_counter_time_bidirectional::sinsp_counter_time_bidirectional(
	const sinsp_counter_time_bidirectional& other)
	: sinsp_counter_percentile_in_out()
	, m_count_in(other.m_count_in)
	, m_count_out(other.m_count_out)
	, m_count_other(other.m_count_other)
	, m_time_ns_in(other.m_time_ns_in)
	, m_time_ns_out(other.m_time_ns_out)
	, m_time_ns_other(other.m_time_ns_other)
{
	m_percentile_in.reset( other.m_percentile_in  ? new percentile(*other.m_percentile_in)  : nullptr);
	m_percentile_out.reset(other.m_percentile_out ? new percentile(*other.m_percentile_out) : nullptr);
}

sinsp_counter_time_bidirectional& sinsp_counter_time_bidirectional::operator=(sinsp_counter_time_bidirectional &other)
{
	if(this != &other)
	{
		m_count_in = other.m_count_in;
		m_count_out = other.m_count_out;
		m_count_other = other.m_count_other;
		m_time_ns_in = other.m_time_ns_in;
		m_time_ns_out = other.m_time_ns_out;
		m_time_ns_other = other.m_time_ns_other;
		if(other.m_percentile_in)
		{
			m_percentile_in = std::move(other.m_percentile_in);
		}
		if(other.m_percentile_out)
		{
			m_percentile_out = std::move(other.m_percentile_out);
		}
	}
	return *this;
}

void sinsp_counter_time_bidirectional::add_in(uint32_t cnt_delta, uint64_t time_delta)
{
	ASSERT(cnt_delta <= 1);

	m_count_in += cnt_delta;
	m_time_ns_in += time_delta;
	if(m_percentile_in)
	{
		m_percentile_in->add(time_delta);
	}
}

void sinsp_counter_time_bidirectional::add_out(uint32_t cnt_delta, uint64_t time_delta)
{
	ASSERT(cnt_delta <= 1);

	m_count_out += cnt_delta;
	m_time_ns_out += time_delta;
	if(m_percentile_out)
	{
		m_percentile_out->add(time_delta);
	}
}

void sinsp_counter_time_bidirectional::add_other(uint32_t cnt_delta, uint64_t time_delta)
{
	ASSERT(cnt_delta <= 1);

	m_count_other += cnt_delta;
	m_time_ns_other += time_delta;
}

void sinsp_counter_time_bidirectional::add(sinsp_counter_time_bidirectional* other)
{
	ASSERT(other);
	m_count_in += other->m_count_in;
	m_count_out += other->m_count_out;
	m_count_other += other->m_count_other;
	m_time_ns_in += other->m_time_ns_in;
	m_time_ns_out += other->m_time_ns_out;
	m_time_ns_other += other->m_time_ns_other;

	// merge the corresponding percentile stores if there are unique
	if(m_percentile_in && other->m_percentile_in &&
	   (m_percentile_in != other->m_percentile_in))
	{
		m_percentile_in->merge(other->m_percentile_in.get());
	}
	if(m_percentile_out && other->m_percentile_out &&
	   (m_percentile_out != other->m_percentile_out))
	{
		m_percentile_out->merge(other->m_percentile_out.get());
	}
}

void sinsp_counter_time_bidirectional::clear()
{
	m_count_in = 0;
	m_count_out = 0;
	m_count_other = 0;
	m_time_ns_in = 0;
	m_time_ns_out = 0;
	m_time_ns_other = 0;
	if(m_percentile_in)
	{
		m_percentile_in->reset();
	}
	if(m_percentile_out)
	{
		m_percentile_out->reset();
	}
}

void sinsp_counter_time_bidirectional::to_protobuf(draiosproto::counter_time_bidirectional* protobuf_msg, uint32_t sampling_ratio) const
{
	protobuf_msg->set_time_ns_in(m_time_ns_in * sampling_ratio);
	protobuf_msg->set_time_ns_out(m_time_ns_out * sampling_ratio);
	protobuf_msg->set_count_in(m_count_in * sampling_ratio);
	protobuf_msg->set_count_out(m_count_out * sampling_ratio);
	// NOTE: other is not included because we don't need it in the sample, just for internal use

	// percentiles
	typedef draiosproto::counter_time_bidirectional CTB;
	typedef draiosproto::counter_percentile CP;
	typedef draiosproto::counter_percentile_data CPD;
	if(m_percentile_in && m_percentile_in->sample_count())
	{
		m_percentile_in->to_protobuf<CTB, CP, CPD>(protobuf_msg,
		                                           &CTB::add_percentile_in,
		                                           (!m_serialize_pctl_data) ? nullptr :
		                                           &CTB::mutable_percentile_in_data);
	}
	if(m_percentile_out && m_percentile_out->sample_count())
	{
		m_percentile_out->to_protobuf<CTB, CP, CPD>(protobuf_msg,
		                                            &CTB::add_percentile_out,
		                                            (!m_serialize_pctl_data) ? nullptr :
		                                            &CTB::mutable_percentile_out_data);
	}
}

void sinsp_counter_time_bidirectional::coalesce_protobuf_add(draiosproto::counter_time_bidirectional* protobuf_msg,
							     uint32_t sampling_ratio) const
{
	protobuf_msg->set_time_ns_in(protobuf_msg->time_ns_in() + m_time_ns_in * sampling_ratio);
	protobuf_msg->set_time_ns_out(protobuf_msg->time_ns_out() + m_time_ns_out * sampling_ratio);
	protobuf_msg->set_count_in(protobuf_msg->count_in() + m_count_in * sampling_ratio);
	protobuf_msg->set_count_out(protobuf_msg->count_out() + m_count_out * sampling_ratio);
}

void sinsp_counter_time_bidirectional::coalesce_protobuf_max(draiosproto::counter_time_bidirectional* protobuf_msg,
							     uint32_t sampling_ratio) const
{
	protobuf_msg->set_time_ns_in(std::max(protobuf_msg->time_ns_in(), m_time_ns_in * sampling_ratio));
	protobuf_msg->set_time_ns_out(std::max(protobuf_msg->time_ns_out(), m_time_ns_out * sampling_ratio));
	protobuf_msg->set_count_in(std::max(protobuf_msg->count_in(), m_count_in * sampling_ratio));
	protobuf_msg->set_count_out(std::max(protobuf_msg->count_out(), m_count_out * sampling_ratio));
}
uint32_t sinsp_counter_time_bidirectional::get_tot_count() const
{
	return m_count_in + m_count_out + m_count_other;
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_counter_bytes implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_counter_bytes::sinsp_counter_bytes()
{
	clear();
}

void sinsp_counter_bytes::add_in(uint32_t cnt_delta, uint32_t bytes_delta)
{
	ASSERT(cnt_delta <= 1);

	m_count_in += cnt_delta;
	m_bytes_in += bytes_delta;
}

void sinsp_counter_bytes::add_out(uint32_t cnt_delta, uint32_t bytes_delta)
{
	ASSERT(cnt_delta <= 1);

	m_count_out += cnt_delta;
	m_bytes_out += bytes_delta;
}

void sinsp_counter_bytes::add(sinsp_counter_bytes* other)
{
	m_count_in += other->m_count_in;
	m_count_out += other->m_count_out;
	m_bytes_in += other->m_bytes_in;
	m_bytes_out += other->m_bytes_out;
}

void sinsp_counter_bytes::clear()
{
	m_count_in = 0;
	m_count_out = 0;
	m_bytes_in = 0;
	m_bytes_out = 0;
}

void sinsp_counter_bytes::to_protobuf(draiosproto::counter_bytes* protobuf_msg, uint32_t sampling_ratio) const
{
	protobuf_msg->set_bytes_in(m_bytes_in * sampling_ratio);
	protobuf_msg->set_bytes_out(m_bytes_out * sampling_ratio);
	protobuf_msg->set_count_in(m_count_in * sampling_ratio);
	protobuf_msg->set_count_out(m_count_out * sampling_ratio);
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_counter_time_bytes implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_counter_time_bytes::sinsp_counter_time_bytes(
	const std::set<double>* percentiles,
	const sinsp_counter_percentile_in_out *shared)
	: sinsp_counter_percentile_in_out(percentiles, shared)
{
	clear();
}

sinsp_counter_time_bytes::~sinsp_counter_time_bytes()
{
}

sinsp_counter_time_bytes::sinsp_counter_time_bytes(const sinsp_counter_time_bytes& other)
	: sinsp_counter_percentile_in_out()
	, m_count_in(other.m_count_in)
	, m_count_out(other.m_count_out)
	, m_count_other(other.m_count_other)
	, m_time_ns_in(other.m_time_ns_in)
	, m_time_ns_out(other.m_time_ns_out)
	, m_time_ns_other(other.m_time_ns_other)
	, m_bytes_in(other.m_bytes_in)
	, m_bytes_out(other.m_bytes_out)
	, m_bytes_other(other.m_bytes_other)
{
	m_percentile_in.reset( other.m_percentile_in  ? new percentile(*other.m_percentile_in)  : nullptr);
	m_percentile_out.reset(other.m_percentile_out ? new percentile(*other.m_percentile_out) : nullptr);
}

sinsp_counter_time_bytes& sinsp_counter_time_bytes::operator=(sinsp_counter_time_bytes &other)
{
	if(this != &other)
	{
		m_count_in = other.m_count_in;
		m_count_out = other.m_count_out;
		m_count_other = other.m_count_other;
		m_time_ns_in = other.m_time_ns_in;
		m_time_ns_out = other.m_time_ns_out;
		m_time_ns_other = other.m_time_ns_other;
		m_bytes_in = other.m_bytes_in;
		m_bytes_out = other.m_bytes_out;
		m_bytes_other = other.m_count_other;
		if(other.m_percentile_in)
		{
			m_percentile_in = std::move(other.m_percentile_in);
		}
		if(other.m_percentile_out)
		{
			m_percentile_out = std::move(other.m_percentile_out);
		}
	}
	return *this;
}

void sinsp_counter_time_bytes::add_in(uint32_t cnt_delta, uint64_t time_delta, uint32_t bytes_delta)
{
	m_count_in += cnt_delta;
	m_time_ns_in += time_delta;
	m_bytes_in += bytes_delta;
	if(m_percentile_in)
	{
		m_percentile_in->add(time_delta);
	}
}

void sinsp_counter_time_bytes::add_out(uint32_t cnt_delta, uint64_t time_delta, uint32_t bytes_delta)
{
	m_count_out += cnt_delta;
	m_time_ns_out += time_delta;
	m_bytes_out += bytes_delta;
	if(m_percentile_out)
	{
		m_percentile_out->add(time_delta);
	}
}

void sinsp_counter_time_bytes::add_other(uint32_t cnt_delta, uint64_t time_delta, uint32_t bytes_delta)
{
	m_count_other += cnt_delta;
	m_time_ns_other += time_delta;
	m_bytes_other += bytes_delta;
}

void sinsp_counter_time_bytes::add(sinsp_counter_time_bytes* other)
{
	m_count_in += other->m_count_in;
	m_count_out += other->m_count_out;
	m_count_other += other->m_count_other;
	m_time_ns_in += other->m_time_ns_in;
	m_time_ns_out += other->m_time_ns_out;
	m_time_ns_other += other->m_time_ns_other;
	m_bytes_in += other->m_bytes_in;
	m_bytes_out += other->m_bytes_out;
	m_bytes_other += other->m_bytes_other;

	// merge the corresponding percentile stores if there are unique
	if(m_percentile_in && other->m_percentile_in &&
	   (m_percentile_in != other->m_percentile_in))
	{
		m_percentile_in->merge(other->m_percentile_in.get());
	}
	if(m_percentile_out && other->m_percentile_out &&
	   (m_percentile_out != other->m_percentile_out))
	{
		m_percentile_out->merge(other->m_percentile_out.get());
	}
}

void sinsp_counter_time_bytes::add(sinsp_counter_time_bidirectional* other, bool time_only)
{
	if(!time_only)
	{
		m_count_in += other->m_count_in;
		m_count_out += other->m_count_out;
		m_count_other += other->m_count_other;
	}

	m_time_ns_in += other->m_time_ns_in;
	m_time_ns_out += other->m_time_ns_out;
	m_time_ns_other += other->m_time_ns_other;
	if(m_percentile_in && other->m_percentile_in)
	{
		m_percentile_in->merge(other->m_percentile_in.get());
	}
	if(m_percentile_out && other->m_percentile_out)
	{
		m_percentile_out->merge(other->m_percentile_out.get());
	}
}

void sinsp_counter_time_bytes::add(sinsp_counter_time* other)
{
	m_count_other += other->m_count;
	m_time_ns_other += other->m_time_ns;
}

void sinsp_counter_time_bytes::clear()
{
	m_count_in = 0;
	m_count_out = 0;
	m_count_other = 0;
	m_time_ns_in = 0;
	m_time_ns_out = 0;
	m_time_ns_other = 0;
	m_bytes_in = 0;
	m_bytes_out = 0;
	m_bytes_other = 0;
	if(m_percentile_in)
	{
		m_percentile_in->reset();
	}
	if(m_percentile_out)
	{
		m_percentile_out->reset();
	}
}

void sinsp_counter_time_bytes::to_protobuf(draiosproto::counter_time_bytes* protobuf_msg,
					   uint64_t tot_relevant_time_ns,
					   uint32_t sampling_ratio)
{
	protobuf_msg->set_time_ns_in(m_time_ns_in * sampling_ratio);
	protobuf_msg->set_time_ns_out(m_time_ns_out * sampling_ratio);
	protobuf_msg->set_time_ns_other(m_time_ns_other * sampling_ratio);

	if(tot_relevant_time_ns != 0)
	{
		protobuf_msg->set_time_percentage_in((uint32_t)(((double)m_time_ns_in) * 10000 / (tot_relevant_time_ns * sampling_ratio)));
		protobuf_msg->set_time_percentage_out((uint32_t)(((double)m_time_ns_out) * 10000 / (tot_relevant_time_ns * sampling_ratio)));
		protobuf_msg->set_time_percentage_other((uint32_t)(((double)m_time_ns_other) * 10000 / (tot_relevant_time_ns * sampling_ratio)));
	}
	else
	{
		//
		// This can happen in case of gaps longer than 1 second in the event stream
		//
		protobuf_msg->set_time_percentage_in(0);
		protobuf_msg->set_time_percentage_out(0);
		protobuf_msg->set_time_percentage_other(0);
	}

	protobuf_msg->set_count_in(m_count_in * sampling_ratio);
	protobuf_msg->set_count_out(m_count_out * sampling_ratio);
	protobuf_msg->set_count_other(m_count_other * sampling_ratio);


	protobuf_msg->set_bytes_in(m_bytes_in * sampling_ratio);
	protobuf_msg->set_bytes_out(m_bytes_out * sampling_ratio);
	protobuf_msg->set_bytes_other(m_bytes_other * sampling_ratio);

	// percentiles
	typedef draiosproto::counter_time_bytes CTB;
	typedef draiosproto::counter_percentile CP;
	typedef draiosproto::counter_percentile_data CPD;
	if(m_percentile_in && m_percentile_in->sample_count())
	{
		m_percentile_in->to_protobuf<CTB, CP, CPD>(protobuf_msg,
		                                           &CTB::add_percentile_in,
		                                           (!m_serialize_pctl_data) ? nullptr :
		                                           &CTB::mutable_percentile_in_data);
	}
	if(m_percentile_out && m_percentile_out->sample_count())
	{
		m_percentile_out->to_protobuf<CTB, CP, CPD>(protobuf_msg,
		                                            &CTB::add_percentile_out,
		                                            (!m_serialize_pctl_data) ? nullptr :
		                                            &CTB::mutable_percentile_out_data);
	}
}

void sinsp_counter_time_bytes::coalesce_protobuf(draiosproto::counter_time_bytes* protobuf_msg,
					   uint64_t tot_relevant_time_ns,
					   const uint32_t sampling_ratio)
{
	protobuf_msg->set_time_ns_in(protobuf_msg->time_ns_in() + m_time_ns_in * sampling_ratio);
	protobuf_msg->set_time_ns_out(protobuf_msg->time_ns_out() + m_time_ns_out * sampling_ratio);
	protobuf_msg->set_time_ns_other(protobuf_msg->time_ns_other() + m_time_ns_other * sampling_ratio);

	if(tot_relevant_time_ns != 0)
	{
		protobuf_msg->set_time_percentage_in(protobuf_msg->time_percentage_in() + (uint32_t)(((double)m_time_ns_in) * 10000 / (tot_relevant_time_ns * sampling_ratio)));
		protobuf_msg->set_time_percentage_out(protobuf_msg->time_percentage_out() + (uint32_t)(((double)m_time_ns_out) * 10000 / (tot_relevant_time_ns * sampling_ratio)));
		protobuf_msg->set_time_percentage_other(protobuf_msg->time_percentage_other() + (uint32_t)(((double)m_time_ns_other) * 10000 / (tot_relevant_time_ns * sampling_ratio)));
	}

	protobuf_msg->set_count_in(protobuf_msg->count_in() + m_count_in * sampling_ratio);
	protobuf_msg->set_count_out(protobuf_msg->count_out() + m_count_out * sampling_ratio);
	protobuf_msg->set_count_other(protobuf_msg->count_other() + m_count_other * sampling_ratio);


	protobuf_msg->set_bytes_in(protobuf_msg->bytes_in() + m_bytes_in * sampling_ratio);
	protobuf_msg->set_bytes_out(protobuf_msg->bytes_out() + m_bytes_out * sampling_ratio);
	protobuf_msg->set_bytes_other(protobuf_msg->bytes_other() + m_bytes_other * sampling_ratio);
}

uint64_t sinsp_counter_time_bytes::get_tot_bytes() const
{
	return m_bytes_in + m_bytes_out;
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_counters implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_counters::sinsp_counters()
{
	clear();
}

void sinsp_counters::clear()
{
	m_unknown.clear();
	m_other.clear();
	m_file.clear();
	m_net.clear();
	m_ipc.clear();
	m_memory.clear();
	m_process.clear();
	m_sleep.clear();
	m_system.clear();
	m_signal.clear();
	m_user.clear();
	m_time.clear();
	m_io_file.clear();
	m_io_net.clear();
	m_io_other.clear();
	m_wait_file.clear();
	m_wait_net.clear();
	m_wait_ipc.clear();
	m_wait_other.clear();
	m_processing.clear();
}

void sinsp_counters::get_total(sinsp_counter_time* tot)
{
	tot->add(&m_unknown);
	tot->add(&m_other);
	tot->add(&m_file);
	tot->add(&m_net);
	tot->add(&m_ipc);
	tot->add(&m_memory);
	tot->add(&m_process);
	tot->add(&m_sleep);
	tot->add(&m_system);
	tot->add(&m_signal);
	tot->add(&m_user);
	tot->add(&m_time);
	tot->add(&m_io_file);
	tot->add(&m_io_net);
	tot->add(&m_io_other);
	tot->add(&m_wait_file);
	tot->add(&m_wait_net);
	tot->add(&m_wait_ipc);
	tot->add(&m_wait_other);
	tot->add(&m_processing);
}

void sinsp_counters::add(sinsp_counters* other)
{
	m_unknown.add(&other->m_unknown);
	m_other.add(&other->m_other);
	m_file.add(&other->m_file);
	m_net.add(&other->m_net);
	m_ipc.add(&other->m_ipc);
	m_memory.add(&other->m_memory);
	m_process.add(&other->m_process);
	m_sleep.add(&other->m_sleep);
	m_system.add(&other->m_system);
	m_signal.add(&other->m_signal);
	m_user.add(&other->m_user);
	m_time.add(&other->m_time);
	m_io_file.add(&other->m_io_file);
	m_io_net.add(&other->m_io_net);
	m_io_other.add(&other->m_io_other);
	m_wait_file.add(&other->m_wait_file);
	m_wait_net.add(&other->m_wait_net);
	m_wait_ipc.add(&other->m_wait_ipc);
	m_wait_other.add(&other->m_wait_other);
	m_processing.add(&other->m_processing);
}
void sinsp_counters::calculate_totals()
{
	m_tot_other.clear();
	// Unknown is usually garbage caused by drops or processes coming out of
	// inactivity. We just ignore it.
	//m_tot_other.add(&m_unknown);
	m_tot_other.add(&m_other);
	m_tot_other.add(&m_memory);
	m_tot_other.add(&m_process);
	m_tot_other.add(&m_system);
	m_tot_other.add(&m_signal);
	m_tot_other.add(&m_user);
	m_tot_other.add(&m_time);
	//m_tot_other.add(&m_io_other);

	m_tot_wait.clear();
	m_tot_wait.add(&m_wait_other);
	m_tot_wait.add(&m_sleep);

	m_tot_io_file.clear();
	m_tot_io_file.add(&m_file);
	m_tot_io_file.add(&m_io_file);
	m_tot_io_file.add(&m_wait_file, true);

	m_tot_io_net.clear();
	m_tot_io_net.add(&m_net);
	sinsp_counter_time_bytes t_io_net;
	if(m_percentiles.size())
	{
		t_io_net.set_percentiles(m_percentiles);
	}
	t_io_net.add(&m_io_net);
	t_io_net.m_time_ns_in = 0;
	m_tot_io_net.add(&t_io_net);
	m_tot_io_net.add(&m_wait_net, true);

	m_tot_ipc.clear();
	m_tot_ipc.add(&m_ipc);
	m_tot_ipc.add(&m_wait_ipc);

	m_tot_relevant.clear();
	m_tot_relevant.add(&m_tot_other);
	m_tot_relevant.add(&m_tot_io_file);
	m_tot_relevant.add(&m_tot_io_net);
	m_tot_relevant.add(&m_processing);
}

void sinsp_counters::set_percentiles(const std::set<double>& percentiles,
                                     const sinsp_counters *shared)
{
	m_io_file.set_percentiles(percentiles, shared ? &(shared->m_io_file) : nullptr);
	m_io_net.set_percentiles(percentiles, shared ? &(shared->m_io_net) : nullptr);
	m_tot_io_file.set_percentiles(percentiles, shared ? &(shared->m_tot_io_file) : nullptr);
	m_tot_io_net.set_percentiles(percentiles, shared ? &(shared->m_tot_io_net) : nullptr);
	m_percentiles = percentiles;
}

void sinsp_counters::set_serialize_pctl_data(bool val)
{
	m_io_file.set_serialize_pctl_data(val);
	m_io_net.set_serialize_pctl_data(val);
	m_tot_io_file.set_serialize_pctl_data(val);
	m_tot_io_net.set_serialize_pctl_data(val);
}

void sinsp_counters::to_protobuf(draiosproto::time_categories* protobuf_msg, uint32_t sampling_ratio)
{
	calculate_totals();

	m_tot_other.to_protobuf(protobuf_msg->mutable_other(), m_tot_relevant.m_time_ns, sampling_ratio);
	m_tot_io_file.to_protobuf(protobuf_msg->mutable_io_file(), m_tot_relevant.m_time_ns, sampling_ratio);
	m_tot_io_net.to_protobuf(protobuf_msg->mutable_io_net(), m_tot_relevant.m_time_ns, sampling_ratio);
	m_processing.to_protobuf(protobuf_msg->mutable_processing(), m_tot_relevant.m_time_ns, sampling_ratio);

	ASSERT(m_tot_io_file.m_bytes_other == 0);
	ASSERT(m_tot_io_net.m_bytes_other == 0);

#ifdef _DEBUG
	sinsp_counter_time ttot;
	ttot.add(&m_io_other);
	ttot.add(&m_tot_other);
	ttot.add(&m_tot_wait);
	ttot.add(&m_tot_io_file);
	ttot.add(&m_tot_io_net);
	ttot.add(&m_tot_ipc);
	ttot.add(&m_processing);
	ttot.add(&m_unknown);
	ttot.m_time_ns += m_io_net.m_time_ns_in;
#endif
}

void sinsp_counters::coalesce_protobuf(draiosproto::time_categories* protobuf_msg,
				       const uint32_t sampling_ratio,
				       uint64_t& other_denom,
				       uint64_t& processing_denom)
{
	calculate_totals();

	m_tot_other.coalesce_protobuf(protobuf_msg->mutable_other(),
				      m_tot_relevant.m_time_ns,
				      other_denom,
				      sampling_ratio);
	m_tot_io_file.coalesce_protobuf(protobuf_msg->mutable_io_file(),
					m_tot_relevant.m_time_ns,
					sampling_ratio);
	m_tot_io_net.coalesce_protobuf(protobuf_msg->mutable_io_net(),
				       m_tot_relevant.m_time_ns,
				       sampling_ratio);
	m_processing.coalesce_protobuf(protobuf_msg->mutable_processing(),
				       m_tot_relevant.m_time_ns,
				       processing_denom,
				       sampling_ratio);

	ASSERT(m_tot_io_file.m_bytes_other == 0);
	ASSERT(m_tot_io_net.m_bytes_other == 0);
}

void sinsp_counters::to_reqprotobuf(draiosproto::transaction_breakdown_categories* protobuf_msg, uint32_t sampling_ratio)
{
	calculate_totals();

	m_tot_other.to_protobuf(protobuf_msg->mutable_other(), m_tot_relevant.m_time_ns, sampling_ratio);
	m_tot_io_file.to_protobuf(protobuf_msg->mutable_io_file(), m_tot_relevant.m_time_ns, sampling_ratio);
	m_tot_io_net.to_protobuf(protobuf_msg->mutable_io_net(), m_tot_relevant.m_time_ns, sampling_ratio);
	m_processing.to_protobuf(protobuf_msg->mutable_processing(), m_tot_relevant.m_time_ns, sampling_ratio);

#ifdef _DEBUG
	sinsp_counter_time ttot;
	ttot.add(&m_io_other);
	ttot.add(&m_tot_other);
	ttot.add(&m_tot_wait);
	ttot.add(&m_tot_io_file);
	ttot.add(&m_tot_io_net);
	ttot.add(&m_tot_ipc);
	ttot.add(&m_processing);
	ttot.add(&m_unknown);
	ttot.m_time_ns += m_io_net.m_time_ns_in;
#endif
}

void sinsp_counters::coalesce_reqprotobuf(draiosproto::transaction_breakdown_categories* protobuf_msg, 
					  uint32_t sampling_ratio,
					  uint64_t& other_denom,
					  uint64_t& processing_denom)
{
	calculate_totals();

	m_tot_other.coalesce_protobuf(protobuf_msg->mutable_other(),
				      m_tot_relevant.m_time_ns,
				      other_denom,
				      sampling_ratio);
	m_tot_io_file.coalesce_protobuf(protobuf_msg->mutable_io_file(),
					m_tot_relevant.m_time_ns,
					sampling_ratio);
	m_tot_io_net.coalesce_protobuf(protobuf_msg->mutable_io_net(),
				       m_tot_relevant.m_time_ns,
				       sampling_ratio);
	m_processing.coalesce_protobuf(protobuf_msg->mutable_processing(),
				       m_tot_relevant.m_time_ns,
				       processing_denom,
				       sampling_ratio);
}

uint64_t sinsp_counters::get_total_other_time()
{
	return m_tot_other.m_time_ns;
}

uint64_t sinsp_counters::get_total_wait_time()
{
	return m_tot_wait.m_time_ns;
}

uint64_t sinsp_counters::get_total_file_time()
{
	return m_tot_io_file.m_time_ns_in + m_tot_io_file.m_time_ns_out + m_tot_io_file.m_time_ns_other;
}

uint64_t sinsp_counters::get_total_net_time()
{
	return m_tot_io_net.m_time_ns_in + m_tot_io_net.m_time_ns_out + m_tot_io_net.m_time_ns_other;
}

uint64_t sinsp_counters::get_total_ipc_time()
{
	return m_tot_ipc.m_time_ns;
}

double sinsp_counters::get_processing_percentage()
{
	if(m_tot_relevant.m_time_ns != 0)
	{
		return ((double)m_processing.m_time_ns) / m_tot_relevant.m_time_ns;
	}
	else
	{
		return 0;
	}
}

double sinsp_counters::get_file_percentage()
{
	if(m_tot_relevant.m_time_ns != 0)
	{
		return ((double)m_tot_io_file.m_time_ns_in + m_tot_io_file.m_time_ns_out + m_tot_io_file.m_time_ns_other) / m_tot_relevant.m_time_ns;
	}
	else
	{
		return 0;
	}
}

double sinsp_counters::get_net_percentage()
{
	if(m_tot_relevant.m_time_ns != 0)
	{
		return ((double)m_tot_io_net.m_time_ns_in + m_tot_io_net.m_time_ns_out + m_tot_io_net.m_time_ns_other) / m_tot_relevant.m_time_ns;
	}
	else
	{
		return 0;
	}
}

double sinsp_counters::get_other_percentage()
{
	if(m_tot_relevant.m_time_ns != 0)
	{
		return ((double)m_tot_other.m_time_ns) / m_tot_relevant.m_time_ns;
	}
	else
	{
		return 0;
	}
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_transaction_counters implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_transaction_counters::sinsp_transaction_counters(
	const std::set<double>* percentiles,
	const sinsp_transaction_counters *shared)
	: m_counter(percentiles, shared ? &(shared->m_counter) : nullptr)
{
}

void sinsp_transaction_counters::clear()
{
	m_counter.clear();
	//m_min_counter.clear();
	m_max_counter.clear();
}

void sinsp_transaction_counters::set_percentiles(
	const std::set<double>& percentiles,
	const sinsp_transaction_counters *shared)
{
	m_counter.set_percentiles(percentiles, shared ? &(shared->m_counter) : nullptr);
	m_has_percentiles = (percentiles.size() != 0);
}

void sinsp_transaction_counters::set_serialize_pctl_data(bool val)
{
	m_counter.set_serialize_pctl_data(val);
}

void sinsp_transaction_counters::to_protobuf(draiosproto::counter_time_bidirectional* protobuf_msg, 
					     draiosproto::counter_time_bidirectional* max_protobuf_msg, 
					     uint32_t sampling_ratio) const
{
	m_counter.to_protobuf(protobuf_msg, sampling_ratio);
	m_max_counter.to_protobuf(max_protobuf_msg, 1);
}

void sinsp_transaction_counters::coalesce_protobuf(draiosproto::counter_time_bidirectional* protobuf_msg, 
						   draiosproto::counter_time_bidirectional* max_protobuf_msg, 
						   uint32_t sampling_ratio) const
{
	m_counter.coalesce_protobuf_add(protobuf_msg, sampling_ratio);
	m_max_counter.coalesce_protobuf_max(max_protobuf_msg, 1);
}

void sinsp_transaction_counters::add(sinsp_transaction_counters* other)
{
	if(m_max_counter.m_count_in == 0 || 
		(other->m_max_counter.m_count_in != 0 &&
		other->m_max_counter.m_time_ns_in > m_max_counter.m_time_ns_in))
	{
		m_max_counter.m_count_in = other->m_max_counter.m_count_in;
		m_max_counter.m_time_ns_in = other->m_max_counter.m_time_ns_in;
	}

	if(m_max_counter.m_count_out == 0 || 
		(other->m_max_counter.m_count_out != 0 &&
		other->m_max_counter.m_time_ns_out > m_max_counter.m_time_ns_out))
	{
		m_max_counter.m_count_out = other->m_max_counter.m_count_out;
		m_max_counter.m_time_ns_out = other->m_max_counter.m_time_ns_out;
	}

	m_counter.add(&other->m_counter);
}

void sinsp_transaction_counters::add_in(uint32_t cnt_delta, uint64_t time_delta)
{
	ASSERT(cnt_delta == 1);
	if(cnt_delta == 1)
	{
		/*if(m_min_counter.m_count_in == 0 || 
			time_delta < m_min_counter.m_time_ns_in)
		{
			m_min_counter.m_count_in = cnt_delta;
			m_min_counter.m_time_ns_in = time_delta;
		}*/

		if(m_max_counter.m_count_in == 0 || 
			time_delta > m_max_counter.m_time_ns_in)
		{
			m_max_counter.m_count_in = cnt_delta;
			m_max_counter.m_time_ns_in = time_delta;
		}
	}

	m_counter.add_in(cnt_delta, time_delta);
}

void sinsp_transaction_counters::add_out(uint32_t cnt_delta, uint64_t time_delta)
{
	ASSERT(cnt_delta == 1);
	if(cnt_delta == 1)
	{
		if(m_max_counter.m_count_out == 0 || 
			time_delta > m_max_counter.m_time_ns_out)
		{
			m_max_counter.m_count_out = cnt_delta;
			m_max_counter.m_time_ns_out = time_delta;
		}
	}

	m_counter.add_out(cnt_delta, time_delta);
}

const sinsp_counter_time_bidirectional* sinsp_transaction_counters::get_counter()
{
	return &m_counter;
}
const sinsp_counter_time_bidirectional* sinsp_transaction_counters::get_max_counter()
{
	return &m_max_counter;
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_connection_counters implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_connection_counters::sinsp_connection_counters():
	m_error_count(0)
{ }

void sinsp_connection_counters::clear()
{
	m_server.clear();
	m_client.clear();
	m_error_count = 0;
}

void sinsp_connection_counters::to_protobuf(draiosproto::connection_categories* protobuf_msg, uint32_t sampling_ratio) const
{
	m_server.to_protobuf(protobuf_msg->mutable_server(), sampling_ratio);
	m_client.to_protobuf(protobuf_msg->mutable_client(), sampling_ratio);
}

void sinsp_connection_counters::add(sinsp_connection_counters* other)
{
	m_server.add(&other->m_server);
	m_client.add(&other->m_client);
	m_error_count += other->m_error_count;
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_error_counters implementation
///////////////////////////////////////////////////////////////////////////////
void sinsp_error_counters::clear()
{
	m_count = 0;
	m_count_file = 0;
	m_count_file_open = 0;
	m_count_net = 0;
}

void sinsp_error_counters::add(sinsp_error_counters* other)
{
	m_count += other->m_count;
	m_count_file += other->m_count_file;
	m_count_file_open += other->m_count_file_open;
	m_count_net += other->m_count_net;
}


void sinsp_error_counters::to_protobuf(draiosproto::counter_syscall_errors* protobuf_msg, uint32_t sampling_ratio) const
{
	protobuf_msg->set_count(m_count * sampling_ratio);

	if(m_count_file != 0)
	{
		protobuf_msg->set_count_file(m_count_file * sampling_ratio);
	}

	if(m_count_file_open != 0)
	{
		protobuf_msg->set_count_file_open(m_count_file_open * sampling_ratio);
	}

	if(m_count_net != 0)
	{
		protobuf_msg->set_count_net(m_count_net * sampling_ratio);
	}
}

void sinsp_error_counters::coalesce_protobuf(draiosproto::counter_syscall_errors* protobuf_msg,
					     uint32_t sampling_ratio) const
{
	protobuf_msg->set_count(protobuf_msg->count() + m_count * sampling_ratio);

	if(m_count_file != 0)
	{
		protobuf_msg->set_count_file(protobuf_msg->count_file() + m_count_file * sampling_ratio);
	}

	if(m_count_file_open != 0)
	{
		protobuf_msg->set_count_file_open(protobuf_msg->count_file_open() + m_count_file_open * sampling_ratio);
	}

	if(m_count_net != 0)
	{
		protobuf_msg->set_count_net(protobuf_msg->count_net() + m_count_net * sampling_ratio);
	}
}
///////////////////////////////////////////////////////////////////////////////
// sinsp_syscall_counters implementation
///////////////////////////////////////////////////////////////////////////////
void sinsp_syscall_counters::clear()
{
	m_calls.fill(0);
	m_total_calls = 0;
}

std::map<uint64_t, uint16_t> sinsp_syscall_counters::top_calls(uint16_t count) const
{
	std::map<uint64_t, uint16_t> top_calls;

	for (uint16_t type = 0; type < m_calls.max_size(); type++)
	{
		auto cnt = m_calls[type];
		auto output_type = type * 2;

		if (cnt == 0)
		{
			continue;
		}
		else if (top_calls.size() < count)
		{
			top_calls[cnt] = output_type;
			continue;
		}
		else if (cnt > top_calls.cbegin()->first)
		{
			top_calls.erase(top_calls.begin());
			top_calls[cnt] = output_type;
		}
	}

	return top_calls;
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_host_metrics implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_host_metrics::sinsp_host_metrics()
{
	m_protostate = new sinsp_protostate();
	clear();
}

sinsp_host_metrics::~sinsp_host_metrics()
{
	delete m_protostate;
}

void sinsp_host_metrics::clear()
{
	m_metrics.clear();
	m_connection_queue_usage_pct = 0;
	m_fd_usage_pct = 0;
	m_syscall_count.clear();
	m_syscall_errors.clear();
	m_tot_capacity_score = -1;
	m_tot_stolen_capacity_score = -1;
	m_tot_server_transactions = 0;
	m_pfmajor = 0;
	m_pfminor = 0;
	m_protostate->clear();
	m_fd_count = 0;
	m_res_memory_used_kb = 0;
	m_res_memory_free_kb = 0;
	m_swap_memory_used_kb = 0;
	m_swap_memory_total_kb = 0;
	m_swap_memory_avail_kb = 0;
	m_cpuload = 0;
	m_proc_count = 0;
	m_proc_start_count = 0;
	m_threads_count = 0;
}

void sinsp_host_metrics::add(sinsp_procinfo* pinfo)
{
	m_metrics.add(&pinfo->m_proc_metrics);

	if(pinfo->m_connection_queue_usage_pct > m_connection_queue_usage_pct)
	{
		m_connection_queue_usage_pct = pinfo->m_connection_queue_usage_pct;
	}

	if(pinfo->m_fd_usage_pct > m_fd_usage_pct)
	{
		m_fd_usage_pct = pinfo->m_fd_usage_pct;
	}

	m_pfmajor += pinfo->m_pfmajor;
	m_pfminor += pinfo->m_pfminor;
	m_res_memory_used_kb += pinfo->m_vmrss_kb;
	m_swap_memory_used_kb += pinfo->m_vmswap_kb;
	
	if(pinfo->m_cpuload >= 0)
	{
		m_cpuload += pinfo->m_cpuload;
	}

	m_protostate->add(&(pinfo->m_protostate));

	m_fd_count += pinfo->m_fd_count;
	m_proc_count += pinfo->m_proc_count;
	m_proc_start_count += pinfo->m_start_count;
	m_threads_count += pinfo->m_threads_count;
}

void sinsp_host_metrics::add_capacity_score(float capacity_score, 
					    float stolen_capacity_score,
					    uint32_t n_server_transactions)
{
	if(capacity_score > m_tot_capacity_score)
	{
		m_tot_capacity_score = capacity_score;
		m_tot_stolen_capacity_score = stolen_capacity_score;
	}
}

double sinsp_host_metrics::get_capacity_score() const
{
	return m_tot_capacity_score;
}

double sinsp_host_metrics::get_stolen_score() const
{
	return m_tot_stolen_capacity_score;
}

void sinsp_host_metrics::set_percentiles(const std::set<double>& percentiles)
{
	m_metrics.set_percentiles(percentiles);
}

void sinsp_host_metrics::set_serialize_pctl_data(bool val)
{
	m_metrics.set_serialize_pctl_data(val);
}
