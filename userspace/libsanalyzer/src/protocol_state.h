#pragma once
#include "draios.pb.h"
#include "percentile.h"

///////////////////////////////////////////////////////////////////////////////
// Table entries
///////////////////////////////////////////////////////////////////////////////
typedef enum sinsp_request_flags
{
    SRF_NONE = 0,
    SRF_INCLUDE_IN_SAMPLE = 1
} sinsp_request_flags;

class sinsp_request_details
{
public:
    typedef std::shared_ptr<percentile> percentile_ptr_t;

    sinsp_request_details()
        : m_ncalls(0),
          m_nerrors(0),
          m_time_max(0),
          m_bytes_in(0),
          m_bytes_out(0),
          m_flags(SRF_NONE),
          m_time_tot(0),
          m_percentile(nullptr)
    {
    }

    sinsp_request_details(const sinsp_request_details& other)
        : m_ncalls(other.m_ncalls),
          m_nerrors(other.m_nerrors),
          m_time_max(other.m_time_max),
          m_bytes_in(other.m_bytes_in),
          m_bytes_out(other.m_bytes_out),
          m_flags(other.m_flags),
          m_time_tot(other.m_time_tot),
          // ensure each instance has its own percentiles
          m_percentile(other.m_percentile ? new percentile(*other.m_percentile) : nullptr)
    {
    }

    sinsp_request_details& operator=(sinsp_request_details other)
    {
        if (this != &other)
        {
            m_ncalls = other.m_ncalls;
            m_nerrors = other.m_nerrors;
            m_time_max = other.m_time_max;
            m_bytes_in = other.m_bytes_in;
            m_bytes_out = other.m_bytes_out;
            m_flags = other.m_flags;
            m_time_tot = other.m_time_tot;
            // since we already have a disposable copy here, it's ok to just move it
            m_percentile = other.m_percentile;
        }
        return *this;
    }

    sinsp_request_details& operator+=(const sinsp_request_details& other)
    {
        if (m_ncalls == 0)
        {
            *this = other;
        }
        else
        {
            m_ncalls += other.m_ncalls;
            m_nerrors += other.m_nerrors;
            add_times(other);
            m_bytes_in += other.m_bytes_in;
            m_bytes_out += other.m_bytes_out;

            if (other.m_time_max > m_time_max)
            {
                m_time_max = other.m_time_max;
            }
        }
        return *this;
    }

    ~sinsp_request_details() {}

    inline void to_protobuf(draiosproto::counter_proto_entry* counters,
                            uint32_t sampling_ratio,
                            std::function<void(const percentile_ptr_t)> pctl_to_protobuf) const
    {
        counters->set_ncalls(m_ncalls * sampling_ratio);
        counters->set_time_tot(m_time_tot * sampling_ratio);
        counters->set_time_max(m_time_max);
        counters->set_bytes_in(m_bytes_in * sampling_ratio);
        counters->set_bytes_out(m_bytes_out * sampling_ratio);
        counters->set_nerrors(m_nerrors * sampling_ratio);
        pctl_to_protobuf(m_percentile);
    }

    inline void coalesce_protobuf(draiosproto::counter_proto_entry* counters,
                                  uint32_t sampling_ratio) const
    {
        counters->set_ncalls(counters->ncalls() + m_ncalls * sampling_ratio);
        counters->set_time_tot(counters->time_tot() + m_time_tot * sampling_ratio);
        counters->set_time_max(std::max(m_time_max, counters->time_max()));
        counters->set_bytes_in(counters->bytes_in() + m_bytes_in * sampling_ratio);
        counters->set_bytes_out(counters->bytes_out() + m_bytes_out * sampling_ratio);
        counters->set_nerrors(counters->nerrors() + m_nerrors * sampling_ratio);
    }

    void add_time(uint64_t time_delta)
    {
        m_time_tot += time_delta;
        if (m_percentile)
        {
            m_percentile->add(time_delta);
        }
    }

    void add_times(const sinsp_request_details& other)
    {
        m_time_tot += other.m_time_tot;
        if (m_percentile && other.m_percentile)
        {
            m_percentile->merge(other.m_percentile.get());
        }
    }

    uint64_t get_ncalls() const { return m_ncalls; }

    uint64_t get_time_tot() const { return m_time_tot; }

    void set_percentiles(const std::set<double>& percentiles)
    {
        if (percentiles.size())
        {
            m_percentile.reset(new percentile(percentiles));
        }
    }

    percentile_ptr_t get_percentiles() { return m_percentile; }

    uint32_t m_ncalls;     // number of times this request has been served
    uint32_t m_nerrors;    // number of times serving this request has generated an error
    uint64_t m_time_max;   // slowest time spent serving this request
    uint32_t m_bytes_in;   // received bytes for this request
    uint32_t m_bytes_out;  // sent bytes for this request
    sinsp_request_flags m_flags;

private:
    uint64_t m_time_tot;  // total time spent serving this request
    percentile_ptr_t m_percentile;
};


class protocol_state
{
public:
    protocol_state() : m_serialize_pctl_data(false) {}

    void set_serialize_pctl_data(bool val) { m_serialize_pctl_data = val; }

    void set_percentiles(const std::set<double>& pctls) { m_percentiles = pctls; }

    const std::set<double>& get_percentiles() { return m_percentiles; }

    void percentile_to_protobuf(draiosproto::counter_proto_entry* protoent,
                                sinsp_request_details::percentile_ptr_t pct)
    {
        typedef draiosproto::counter_proto_entry CTB;
        typedef draiosproto::counter_percentile CP;
        typedef draiosproto::counter_percentile_data CPD;
        if (pct && pct->sample_count())
        {
            pct->to_protobuf<CTB, CP, CPD>(
                protoent,
                &CTB::add_percentile,
                (!m_serialize_pctl_data) ? nullptr : &CTB::mutable_percentile_data);
        }
    }

protected:
    std::set<double> m_percentiles;
    bool m_serialize_pctl_data;
};
