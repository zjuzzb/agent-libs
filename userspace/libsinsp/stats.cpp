////////////////////////////////////////////////////////////////////////////
// Public definitions for the scap library
////////////////////////////////////////////////////////////////////////////
#include "sinsp.h"
#include "sinsp_int.h"

#ifdef GATHER_INTERNAL_STATS

void sinsp_stats::clear()
{
	m_n_seen_evts = 0;
	m_n_drops = 0;
	m_n_preemptions = 0;
	m_n_noncached_fd_lookups = 0;
	m_n_cached_fd_lookups = 0;
	m_n_failed_fd_lookups = 0;
	m_n_threads = 0;
	m_n_fds = 0;
	m_n_added_fds = 0;
	m_n_removed_fds = 0;
	m_n_stored_evts = 0;
	m_n_store_drops = 0;
	m_n_retrieved_evts = 0;
	m_n_retrieve_drops = 0;
	m_n_transactions = 0;
	m_n_added_transactions = 0;
	m_n_removed_transactions = 0;
	m_n_pending_transactions = 0;
	m_n_added_pending_transactions = 0;
	m_n_removed_pending_transactions = 0;
	m_n_connections = 0;
	m_n_added_connections = 0;
	m_n_removed_connections = 0;
	m_n_expired_connections = 0;
	m_n_connection_lookups = 0;
	m_n_failed_connection_lookups = 0;
	m_metrics_registry.clear_all_metrics();
}

void sinsp_stats::emit(FILE* f)
{
	m_output_target = f;

	fprintf(f, "evts seen by driver: %" PRIu64 "\n", m_n_seen_evts);
	fprintf(f, "drops: %" PRIu64 "\n", m_n_drops);
	fprintf(f, "preemptions: %" PRIu64 "\n", m_n_preemptions);
	fprintf(f, "fd lookups: %" PRIu64 "(%" PRIu64 " cached %" PRIu64 " noncached)\n", 
		m_n_noncached_fd_lookups + m_n_cached_fd_lookups,
		m_n_cached_fd_lookups,
		m_n_noncached_fd_lookups);
	fprintf(f, "failed fd lookups: %" PRIu64 "\n", m_n_failed_fd_lookups);
	fprintf(f, "n. threads: %" PRIu64 "\n", m_n_threads);
	fprintf(f, "n. fds: %" PRIu64 "\n", m_n_fds);
	fprintf(f, "added fds: %" PRIu64 "\n", m_n_added_fds);
	fprintf(f, "removed fds: %" PRIu64 "\n", m_n_removed_fds);
	fprintf(f, "stored evts: %" PRIu64 "\n", m_n_stored_evts);
	fprintf(f, "store drops: %" PRIu64 "\n", m_n_store_drops);
	fprintf(f, "retrieved evts: %" PRIu64 "\n", m_n_retrieved_evts);
	fprintf(f, "retrieve drops: %" PRIu64 "\n", m_n_retrieve_drops);
	fprintf(f, "n. transactions: %" PRIu64 "\n", m_n_transactions);
	fprintf(f, "added transactions: %" PRIu64 "\n", m_n_added_transactions);
	fprintf(f, "removed transactions: %" PRIu64 "\n", m_n_removed_transactions);
	fprintf(f, "n. pending transactions: %" PRIu64 "\n", m_n_pending_transactions);
	fprintf(f, "added pending transactions: %" PRIu64 "\n", m_n_added_pending_transactions);
	fprintf(f, "removed pending transactions: %" PRIu64 "\n", m_n_removed_pending_transactions);
	fprintf(f, "added connections: %" PRIu64 "\n", m_n_added_connections);
	fprintf(f, "removed connections: %" PRIu64 "\n", m_n_removed_connections);
	fprintf(f, "expired connections: %" PRIu64 "\n", m_n_expired_connections);
	fprintf(f, "connection lookups: %" PRIu64 "\n", m_n_connection_lookups);
	fprintf(f, "failed connection lookups: %" PRIu64 "\n", m_n_failed_connection_lookups);

	for(internal_metrics::registry::metric_map_iterator_t it = m_metrics_registry.get_metrics().begin(); it != m_metrics_registry.get_metrics().end(); it++)
	{
		fprintf(f, "%s: ", it->first.get_description().c_str());
		it->second->process(*this);
	}
}

void sinsp_stats::process(internal_metrics::counter& metric)
{
	fprintf(m_output_target, "%" PRIu64 "\n", metric.get_value());
}

#endif // GATHER_INTERNAL_STATS
