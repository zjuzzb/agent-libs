#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_int.h"

#ifdef HAS_ANALYZER

//#define SQL_DEBUG_SLICE 1

/// this struct represents a C string slice with an explicit length
/// (not NUL-terminated). It's used all over the parser to represent
/// currently evaluated substrings
/// when SQL_DEBUG_SLICE above is enabled, we additionally:
/// - store the actual beginning of the allocated string, so that we can
///   dump the slice as a substring of the original query
/// - run sanity checks on substring operations; all the *chomp methods
///   return a new (smaller) substring and we verify that the cutting
///   point lies inside the original slice.
struct str_slice {
#ifdef SQL_DEBUG_SLICE
	const char *orig_buf; // never modified, for debug purposes
#endif
	const char *start;
	const char *end;

#ifdef SQL_DEBUG_SLICE
	str_slice(const char *start, const char *end) : str_slice(start, start, end)
	{
	}

	str_slice(const char *orig_buf, const char *start, const char *end) :
		orig_buf(orig_buf),
		start(start),
		end(end)
	{
		if (!orig_buf) abort();
		if (start < orig_buf) abort();
		if (end < orig_buf) abort();
		if (start > orig_buf + strlen(orig_buf)) abort();
		if (end > orig_buf + strlen(orig_buf)) abort();
	}
#else
	str_slice(const char *start, const char *end) :
		start(start),
		end(end)
	{
	}
#endif

	inline size_t len() const { return end - start; }

	/// cut off the slice from the right side,
	/// i.e. shorten the slice while keeping the beginning
	/// in the same place
	inline str_slice rchomp(size_t new_len) const {
		return chomp(start, start+new_len);
	}
	inline str_slice rchomp(const char* new_end) const {
		return chomp(start, new_end);
	}

	/// cut off the slice from the left side,
	/// i.e. advance the beginning of the string while keeping
	/// the end in the same place
	inline str_slice lchomp(size_t skip_len) const {
		return chomp(start+skip_len, end);
	}
	inline str_slice lchomp(const char *new_start) const {
		return chomp(new_start, end);
	}

	inline str_slice chomp(const char *new_start, const char *new_end) const {
#ifdef SQL_DEBUG_SLICE
		if (new_start < start) abort();
		if (new_start > end) abort();
		if (new_end < start) abort();
		if (new_end > end) abort();
		if (new_end < new_start) abort();
		return {orig_start, new_start, new_end};
#else
		return {new_start, new_end};
#endif
	}

	/// only used for debugging; print out the slice
	/// as a colored substring of the original buffer
	///
	/// \param col ANSI color code to highlight (41-46 are most useful)
	void dump(int col=41) const {
#ifdef SQL_DEBUG_SLICE
		const char *p = orig_buf;
		if (len() == 0) return;

		while (*p && *p != '\r' && *p != '\n') {
			if (p==start) {
				printf("\x1b[1;%dm", col);
			}
			if (p==end) {
				printf("\x1b[0;37;40m");
			}
			putc(*p, stdout);
			p++;
		}
		printf("\x1b[0;37;40m\n");
#endif
	}
};

//
// Type of queries
//
constexpr const char TOK_SELECT[] = "SELECT";
constexpr const char TOK_INSERT[] = "INSERT";
constexpr const char TOK_SET[] = "SET";
constexpr const char TOK_CREATE[] = "CREATE";
constexpr const char TOK_DELETE[] = "DELETE";
constexpr const char TOK_DROP[] = "DROP";
constexpr const char TOK_REPLACE[] = "REPLACE";
constexpr const char TOK_UPDATE[] = "UPDATE";
constexpr const char TOK_USE[] = "USE";
constexpr const char TOK_SHOW[] = "SHOW";
constexpr const char TOK_LOCK[] = "LOCK";
constexpr const char TOK_UNLOCK[] = "UNLOCK";
constexpr const char TOK_ALTER[] = "ALTER";

static const std::unordered_map<const char*, sinsp_sql_parser::statement_type> query_types = { // NOLINT(cert-err58-cpp)
	{TOK_SELECT, sinsp_sql_parser::OT_SELECT},
	{TOK_INSERT, sinsp_sql_parser::OT_INSERT},
	{TOK_SET, sinsp_sql_parser::OT_SET},
	{TOK_CREATE, sinsp_sql_parser::OT_CREATE},
	{TOK_DELETE, sinsp_sql_parser::OT_DELETE},
	{TOK_DROP, sinsp_sql_parser::OT_DROP},
	{TOK_REPLACE, sinsp_sql_parser::OT_REPLACE},
	{TOK_UPDATE, sinsp_sql_parser::OT_UPDATE},
	{TOK_USE, sinsp_sql_parser::OT_USE},
	{TOK_SHOW, sinsp_sql_parser::OT_SHOW},
	{TOK_LOCK, sinsp_sql_parser::OT_LOCK},
	{TOK_UNLOCK, sinsp_sql_parser::OT_UNLOCK},
	{TOK_ALTER, sinsp_sql_parser::OT_ALTER},
};

//
// Tokens that denote the end of a select
//
constexpr const char TOK_WHERE[] = "WHERE";
constexpr const char TOK_UNION[] = "UNION";
constexpr const char TOK_EXCEPT[] = "EXCEPT";
constexpr const char TOK_LIMIT[] = "LIMIT";
constexpr const char TOK_GROUP[] = "GROUP";
constexpr const char TOK_HAVING[] = "HAVING";
constexpr const char TOK_ORDER[] = "ORDER";

//
// Tokens that denote the end of an insert
//
constexpr const char TOK_VALUES[] = "VALUES";
// (also SELECT defined above)

//
// Tokens that denote the end of a table clause for different query types
//
constexpr const char TOK_JOIN[] = "JOIN";
constexpr const char TOK_FROM[] = "FROM";
constexpr const char TOK_INTO[] = "INTO";
// (also SET defined above)

/// characters that may be a part of a table name
/// XXX: we should probably also accept "double quotes"
/// and ideally strip backticks, double quotes and everything
/// up to the last . when actually getting the table name
static inline bool sql_istoken(char c)
{
	return isalnum(c) || c == '`' || c == '.' || c == '_';
}

/// one major operation we do all the time while parsing SQL is jumping across whitespace
/// and ()-enclosed blocks. This is a helper function to check for the characters we care about
static inline bool sql_isspace(char c)
{
	return isspace(c) || c == '(' || c == ')';
}

/// skip over whitespace and ()-enclosed blocks, while ignoring the contents of the block
/// completely (when the blocks are neither subqueries nor lists of tables)
/// return a flag whether we saw a bracketed block or not (it's used for parsing
/// SELECT ... FROM (SELECT ...) AS foo
/// properly (we don't want "AS" to be taken for a table name here)
inline bool sinsp_sql_parser::skip_spaces(str_slice& clause)
{
	int inside_paren = 0;
	bool had_parens = false;

	for(; clause.len() > 0; clause.start++)
	{
		if(*clause.start == '(') {
			inside_paren++;
			had_parens = true;
		} else if(*clause.start == ')') {
			--inside_paren;
		} else if (!inside_paren && !isspace(*clause.start)) {
			break;
		}
	}

	return had_parens;
}

/// skip over whitespace and ()-enclosed block, while treating the blocks as potential
/// subqueries or possibly (lists, of, table, names)
/// when we reach the end of the last closing bracket, we try to parse its contents
/// as a subquery (nb. we instantiate a separate parser instance as otherwise it's hard
/// to detect if the parsing succeeded)
/// if the parsing fails and we expect a list of tables here, try to parse it as a FROM
/// clause instead
/// the cases we need to handle here are:
/// - SELECT ... FROM (SELECT ... FROM ...)
/// - SELECT ... FROM (tab1, tab2)
/// - SELECT ... FROM function(arg1, arg2)
///
/// in the last case, we don't want arg1 and arg2 to be treated as table names
/// (want_from_clause will be false when calling this method in that situation)
inline bool sinsp_sql_parser::skip_spaces_rec(str_slice& clause, bool want_from_clause)
{
	int inside_paren = 0;
	const char *paren_start = nullptr;
	auto orig_clause = clause;

	for(;clause.len() > 0; clause.start++)
	{
		if(*clause.start == '(') {
			if (!inside_paren++) {
				paren_start = clause.start+1;
			}
		} else if(*clause.start == ')') {
			if (!--inside_paren) {
				str_slice subquery = orig_clause.chomp(paren_start, clause.start);
				str_slice from_clause = subquery;
				sinsp_sql_parser sp;
				sp.parse_statement(std::move(subquery));
				if (!sp.m_tables.empty()) {
					m_tables.insert(sp.m_tables.begin(), sp.m_tables.end());
				} else if (want_from_clause) {
					parse_from_clause(std::move(from_clause));
				}

			}
		} else if (!inside_paren && !isspace(*clause.start)) {
			break;
		}
	}

	return paren_start != nullptr;
}

/// find the length of the next token (sequence of non-space characters)
/// XXX: `SELECT+1 FROM tab AS plus_one` s valid SQL and we don't
/// parse that correctly (we miss the `SELECT` token)
inline size_t sinsp_sql_parser::next_token_len(str_slice &slice) {
	const char *p = slice.start;
	while (p != slice.end && !sql_isspace(*p)) {
		p++;
	}

	return p - slice.start;
}

/// consume the next token (advance the source slice by the token's length)
/// and return the token as a new slice
inline str_slice sinsp_sql_parser::next_token(str_slice &slice) {
	size_t len = next_token_len(slice);

	auto word = slice.rchomp(len);
	slice = slice.lchomp(len);
	return word;
}

/// check if the next token matches any of the strings passed as the template parameters
/// the main (compile-time) loop is in the `tokenize_impl` function
template<const char *TOK, const char *...Args> inline size_t sinsp_sql_parser::match_token(str_slice &slice,
											   const char *&token) {
	auto word = next_token(slice);
	token = match_token_impl<TOK, Args...>(word);
	return word.len();
}

/// if we're checking the word against just one token, compare the lengths
/// and if they match, the strings themselves
/// we return either the token (a compile-time constant) or nullptr
/// strlen() is evaluated at compile time
template<const char *TOK> inline const char* sinsp_sql_parser::match_token_impl(str_slice &slice) {
	if (slice.len() == strlen(TOK) && sinsp_strcmpi(slice.start, TOK, slice.len())) {
		return TOK;
	}
	return nullptr;
}

/// if there's more than one token to check against the word, check the first one
/// and then recurse into the tail of the token list
template<const char *TOK, const char *TOK2, const char *...Args> inline const char* sinsp_sql_parser::match_token_impl(
	str_slice &slice) {
	auto ret = match_token_impl<TOK>(slice);
	if (ret) {
		return ret;
	}
	return match_token_impl<TOK2, Args...>(slice);
}

/// given a slice, consume everything up to and including TOK, while parsing all bracket-enclosed
/// sequences as subqueries. It's used to find the beginning of the table list, e.g.
/// SELECT ... [FROM table list]
/// INSERT [INTO table list]
/// UPDATE [table list SET]
/// and for looking for JOINs inside the table list
/// when TOK is not found, consume the whole slice
/// (realistically, subqueries can occur probably only in SELECT ... FROM and in JOIN clauses)
template<const char *TOK> inline bool sinsp_sql_parser::find_token(str_slice& slice)
{
	auto tofind_len = strlen(TOK);
	const char* last = slice.end - tofind_len - 1;
	auto bracket_level = 0;
	bool word_boundary = true;
	const char *bracket_start = nullptr;
	const char *str = slice.start;

	for(; str <= last; str++)
	{
		if(*str == '(')
		{
			if (!bracket_level++) {
				bracket_start = str+1;
			}
		}
		else if(*str == ')')
		{
			if (!--bracket_level) {
				parse_statement(slice.chomp(bracket_start, str));
			}
		}

		if(bracket_level == 0 && word_boundary)
		{
			if(sinsp_strcmpi(str, TOK, tofind_len))
			{
				if (str == last || !sql_istoken(str[tofind_len])) {
					slice = slice.lchomp(str+tofind_len);
					return true;
				}
			}
		}
		word_boundary = !sql_istoken(*str);
	}

	slice.start = slice.end;
	return false;
}

/// consume the first token as a table name
inline void sinsp_sql_parser::add_token(str_slice& token)
{
	const char* p = token.start;
	while (p < token.end && sql_istoken(*p)) {
		p++;
	}
	add_table(token.rchomp(p));
	token = token.lchomp(p);
}

/// parse a JOIN clause, i.e. a series of
/// tab1 [LEFT/RIGHT/INNER/OUTER] JOIN tab2 [LEFT/RIGHT/INNER/OUTER] JOIN tab3 ...
/// the first clause (before any JOINs) can be a subquery (XXX: not sure about others)
/// we want _either_ the subquery (if it exists) or the next token (if there's no subquery)
/// as the table name, i.e.
/// ... foo AS f LEFT JOIN bar AS b ...
///     ^^^
/// or
/// ... (SELECT ...) AS subq LEFT JOIN foo AS f ...
///     ^^^^^^^^^^^^
/// here, the token would be "AS" after the subquery so we skip it
inline void sinsp_sql_parser::parse_joins(str_slice&& clause)
{
	bool had_subquery = skip_spaces(clause);
	if(clause.len() == 0)
	{
		return;
	}

	if (!had_subquery) {
		add_token(clause);
	}

	while (clause.len() != 0) {
		if (!find_token<TOK_JOIN>(clause)) {
			break;
		}
		while (clause.start < clause.end && isspace(*clause.start)) {
			clause.start++;
		}
		add_token(clause);
	}
}

/// the FROM clause is a comma-separated list of JOIN clauses, i.e.
/// SELECT ... FROM
/// tab1 LEFT JOIN tab2 ON ..., -- clause 1
/// tab3 INNER JOIN tab4 ON ... -- clause 2
/// realistically, queries use either commas or JOIN clauses, but we have
/// to be ready for both of them
/// XXX: this feels backwards (splitting by JOINs first would feel more natural)
void sinsp_sql_parser::parse_from_clause(str_slice&& clause)
{
	int bracket_level = 0;
	const char* p = clause.start;

	while (p < clause.end) {
		if (bracket_level >= 0 && *p == '(') {
			bracket_level++;
		} else if (bracket_level > 0 && *p == ')') {
			--bracket_level;
		} else if (bracket_level == 0 && *p == ',') {
			// bracket_level == -1 means we found a comma at the top level
			// this is ugly though consistently ~ 1% faster than introducing
			// a dedicated bool variable
			bracket_level = -1;
		} else if (bracket_level == -1 && !isspace(*p)) {
			bracket_level = 0;
			parse_joins(clause.rchomp(p));
			clause = clause.lchomp(p);
		}
		p++;
	}
	parse_joins(std::move(clause));
}

/// find and parse the SELECT ... FROM ... clause
void sinsp_sql_parser::find_select_from_clause(str_slice&& statement)
{
	/// first, skip until the first `FROM` (handling any subqueries found)
	if (!find_token<TOK_FROM>(statement)) {
		return;
	}
	auto orig_query = statement;
	auto prev_query = statement;

	const char *where_start = nullptr;
	const char *where_end = statement.end;

	/// then, find the end of the FROM clause, i.e. any of these tokens
	while(statement.len() != 0)
	{
		const char* token_id;
		auto toklen = match_token<
			TOK_WHERE,
			TOK_LIMIT,
			TOK_GROUP,
			TOK_ORDER,
			TOK_UNION,
			TOK_EXCEPT,
			TOK_HAVING>(statement, token_id);

		/// toklen==0 means we didn't have a preceding token (known or otherwise) before a bracketed
		/// sequence, which means it might be a table list:
		/// ... FROM (tab1, tab2 JOIN tab3) ...
		skip_spaces_rec(statement, toklen==0);

		if(token_id != nullptr)
		{
			/// only the first token marks the actual end of the FROM clause
			if (!where_start) {
				parse_from_clause(orig_query.rchomp(statement.start));
				where_start = statement.start;
			}
			if (token_id == TOK_UNION || token_id == TOK_EXCEPT) {
				/// UNION/EXCEPT marks the end of this query (the rest will be parsed
				/// as a separate query)
				where_end = prev_query.start;
				parse_statement(std::move(prev_query));
				break;
			}
		}
		prev_query = statement;
	}

	if (!where_start) {
		/// if there was no WHERE/LIMIT/etc., the whole chunk from FROM until the end
		/// is the FROM clause
		parse_from_clause(std::move(orig_query));
	} else if (where_start < where_end) {
		/// given our simplistic parsing, we may end up with where_start > where_end
		/// if that's not the case, scan through everything in between for subqueries
		auto where_clause = orig_query.chomp(where_start, where_end);
		while (where_clause.len() != 0)
		{
			auto tok_len = next_token_len(where_clause);
			where_clause = where_clause.lchomp(tok_len);
			skip_spaces_rec(where_clause, tok_len==0);
		}

	}
}

/// we have two major variants of INSERT to handle:
/// - INSERT INTO [tables] VALUES ... (just ignore everything after VALUES)
/// - INSERT INTO [tables] SELECT ... (parse SELECT ... as a subquery)
void sinsp_sql_parser::find_insert_from_clause(str_slice&& statement)
{
	if (!find_token<TOK_INTO>(statement)) {
		return;
	}
	auto orig_clause = statement;
	auto prev_clause = statement;

	while(statement.len() > 0)
	{
		const char* token_id;
		auto toklen = match_token<TOK_SELECT, TOK_VALUES>(statement, token_id);
		skip_spaces_rec(statement, toklen==0);

		if(token_id != nullptr)
		{
			parse_from_clause(orig_clause.rchomp(statement.start));
			if (token_id == TOK_SELECT) {
				parse_statement(std::move(prev_clause));
			}
			return;
		}
		prev_clause = statement;
	}

	/// try to handle leftovers (INSERT INTO ... without VALUES/SELECT)
	parse_from_clause(std::move(orig_clause));
}

/// UPDATE [table] SET ...
/// if we don't find the SET ... part, treat everything as the original
/// table list
/// XXX: we should probably scan for subqueries in the part after SET
void sinsp_sql_parser::find_update_from_clause(str_slice&& statement)
{
	auto set_clause = statement;
	if (find_token<TOK_SET>(set_clause)) {
		parse_from_clause(statement.rchomp(set_clause.start));
	} else {
		parse_from_clause(std::move(statement));
	}
}

/// the main entrypoint for parsing queries
/// this may be called multiple times per `parse` (once per subquery),
/// so it's important not to reset the state here
void sinsp_sql_parser::parse_statement(str_slice&& statement)
{
	statement_type st = OT_NONE;

	while(statement.len() > 0)
	{
		const char *token_id;
		match_token<
			TOK_SELECT,
			TOK_INSERT,
			TOK_SET,
			TOK_CREATE,
			TOK_DELETE,
			TOK_DROP,
			TOK_REPLACE,
			TOK_UPDATE,
			TOK_USE,
			TOK_SHOW,
			TOK_LOCK,
			TOK_UNLOCK,
			TOK_ALTER>(statement, token_id);
		skip_spaces(statement);

		if(token_id != nullptr)
		{
			st = query_types.at(token_id);
			/// in subqueries, don't change the type of the outer query
			if (m_statement_type == OT_NONE)
				m_statement_type = st;
			break;
		}
	}

	switch(st)
	{
		case OT_SELECT:
		case OT_DELETE:
			find_select_from_clause(std::move(statement));
			break;
		case OT_INSERT:
		case OT_REPLACE:
			find_insert_from_clause(std::move(statement));
			break;
		case OT_UPDATE:
			find_update_from_clause(std::move(statement));
			break;
		default:
			break;
	}
}

void sinsp_sql_parser::parse(const char *statement, size_t statement_len)
{
	m_tables.clear();
	m_statement_type = OT_NONE;

	parse_statement({statement, statement + statement_len});
}

string sinsp_sql_parser::tables() const
{
	string s;
	for (const auto& tab : m_tables) {
		if (!s.empty()) {
			s.append(", ");
		}
		s.append(tab);
	}
	return s;
}

/// this is used only in tests, it doesn't need to be fast
const char* sinsp_sql_parser::get_statement_type_string()
{
	for (const auto& qt : query_types) {
		if (m_statement_type == qt.second) {
			return qt.first;
		}
	}
	return "<NA>";
}

inline void sinsp_sql_parser::add_table(str_slice&& table)
{
	if (table.len() == 0) {
		return;
	}

	m_tables.emplace(table.start, table.len());
}
#endif