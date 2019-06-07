#pragma once

#include <set>
#include <string>

struct str_slice;

class sinsp_sql_parser
{
public:
	/// these values are sent directly in protobufs, so they must match
	/// the values in draios.proto (sql_statement_type enum)
	enum statement_type
	{
		OT_NONE = 0,
		OT_SELECT = 1,
		OT_INSERT = 2,
		OT_SET = 3,
		OT_CREATE = 4,
		OT_DELETE = 5,
		OT_DROP = 6,
		OT_REPLACE = 7,
		OT_UPDATE = 8,
		OT_USE = 9,
		OT_SHOW = 10,
		OT_LOCK = 11,
		OT_UNLOCK = 12,
		OT_ALTER = 13
	};

	sinsp_sql_parser() : m_statement_type(OT_NONE)
	{
	}

	/// the main entry point of the parser
	///
	/// \param statement C-style buffer containing the statement (need not be NUL-terminated)
	/// \param statement_len length of the buffer
	///
	/// The method resets the parser state and calls parse_statement()
	void parse(const char *statement, size_t statement_len);

	/// used only in tests, it returns a string describing m_statement_type
	const char* get_statement_type_string();

	statement_type m_statement_type;

	/// the set of table names found in the query
	/// it's kept sorted (by not being an unordered_set) so that we always
	/// return the tables in the same order without having to sort them in .tables()
	std::set<std::string> m_tables;

	/// return the set of tables as a ", "-separated string
	/// we want these to be sorted so that we don't report e.g. "tab1, tab2" for some queries
	/// and "tab2, tab1" for others (we'd then account these as separate tables)
	std::string tables() const;

private:
	void parse_statement(str_slice&& statement);

	void find_select_from_clause(str_slice&& statement);
	void find_insert_from_clause(str_slice&& statement);
	void find_update_from_clause(str_slice&& statement);

	template<const char *TOK> inline bool find_token(str_slice& slice);
	void parse_from_clause(str_slice&& clause);
	inline void parse_joins(str_slice&& clause);
	inline void add_token(str_slice& token);

	inline void add_table(str_slice&& table);

	inline bool skip_spaces(str_slice& clause);
	inline bool skip_spaces_rec(str_slice& clause, bool want_from_clause);

	inline size_t next_token_len(str_slice& slice);
	inline str_slice next_token(str_slice& slice);
	template<const char *TOK, const char *...Args> inline size_t match_token(str_slice &slice, const char *&token);

	template<const char *TOK> inline const char* match_token_impl(str_slice &slice);
	template<const char *TOK, const char *TOK2, const char *...Args> inline const char* match_token_impl(
		str_slice &slice);
};
