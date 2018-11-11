//module vibe.http.internal.hpack.tables;
module hpack.tables;

import vibe.http.status;
import vibe.http.common;
import vibe.core.log;
import vibe.internal.array : FixedRingBuffer;

import std.variant;
import std.traits;
import std.meta;
import std.range;
import std.algorithm.iteration;
import std.math : log10;
import taggedalgebraic;


alias HTTP2SettingValue = uint;

/*
	2.3.  Indexing Tables
	HPACK uses two tables for associating header fields to indexes.  The
	static table (see Section 2.3.1) is predefined and contains common
	header fields (most of them with an empty value).  The dynamic table
	(see Section 2.3.2) is dynamic and can be used by the encoder to
	index header fields repeated in the encoded header lists.
	These two tables are combined into a single address space for
	defining index values (see Section 2.3.3).
 2.3.1.  Static Table
	The static table consists of a predefined static list of header
	fields.  Its entries are defined in Appendix A.
 2.3.2.  Dynamic Table
	The dynamic table consists of a list of header fields maintained in
	first-in, first-out order.  The first and newest entry in a dynamic
	table is at the lowest index, and the oldest entry of a dynamic tabl
	is at the highest index.
	The dynamic table is initially empty.  Entries are added as each
	header block is decompressed.
	The dynamic table is initially empty.  Entries are added as each
	header block is decompressed.
	The dynamic table can contain duplicate entries (i.e., entries with
	the same name and same value).  Therefore, duplicate entries MUST NOT
	be treated as an error by a decoder.
	The encoder decides how to update the dynamic table and as such can
	control how much memory is used by the dynamic table.  To limit the
	memory requirements of the decoder, the dynamic table size is
	strictly bounded (see Section 4.2).
	The decoder updates the dynamic table during the processing of a list
	of header field representations (see Section 3.2).
*/

// wraps a header field = name:value
struct HTTP2HeaderTableField {
	private union HeaderValue {
		string str;
		string[] strarr;
		HTTPStatus status;
		HTTPMethod method;
	}

	string name;
	TaggedAlgebraic!HeaderValue value;
	bool index = true;
	bool neverIndex = false;

	// initializers
	static foreach(t; __traits(allMembers, HeaderValue)) {
		mixin("this(string n, " ~
				typeof(__traits(getMember, HeaderValue, t)).stringof ~
				" v) { name = n; value = v; }");
	}
}

// fixed as per HPACK RFC
immutable size_t STATIC_TABLE_SIZE = 61;

/** static table to index most common headers
  * fixed size, fixed order of entries (read only)
  * cannot be updated while decoding a header block
  */
static immutable HTTP2HeaderTableField[STATIC_TABLE_SIZE+1] StaticTable;

static this() {
	StaticTable = [
		HTTP2HeaderTableField("",""), // 0 index is not allowed
		HTTP2HeaderTableField(":authority", ""),
		HTTP2HeaderTableField(":method", HTTPMethod.GET),
		HTTP2HeaderTableField(":method", HTTPMethod.POST),
		HTTP2HeaderTableField(":path", "/"),
		HTTP2HeaderTableField(":path", "/index.html"),
		HTTP2HeaderTableField(":scheme", "http"),
		HTTP2HeaderTableField(":scheme", "https"),
		HTTP2HeaderTableField(":status", HTTPStatus.ok), 					// 200
		HTTP2HeaderTableField(":status", HTTPStatus.noContent), 				// 204
		HTTP2HeaderTableField(":status", HTTPStatus.partialContent), 		// 206
		HTTP2HeaderTableField(":status", HTTPStatus.notModified), 			// 304
		HTTP2HeaderTableField(":status", HTTPStatus.badRequest), 			// 400
		HTTP2HeaderTableField(":status", HTTPStatus.notFound), 				// 404
		HTTP2HeaderTableField(":status", HTTPStatus.internalServerError), 	// 500
		HTTP2HeaderTableField("accept-charset", ""),
		HTTP2HeaderTableField("accept-encoding", ["gzip", "deflate"]),
		HTTP2HeaderTableField("accept-language", ""),
		HTTP2HeaderTableField("accept-ranges", ""),
		HTTP2HeaderTableField("accept", ""),
		HTTP2HeaderTableField("access-control-allow-origin", ""),
		HTTP2HeaderTableField("age", ""),
		HTTP2HeaderTableField("allow", ""),
		HTTP2HeaderTableField("authorization", ""),
		HTTP2HeaderTableField("cache-control", ""),
		HTTP2HeaderTableField("content-disposition", ""),
		HTTP2HeaderTableField("content-encoding", ""),
		HTTP2HeaderTableField("content-language", ""),
		HTTP2HeaderTableField("content-length", ""),
		HTTP2HeaderTableField("content-location", ""),
		HTTP2HeaderTableField("content-range", ""),
		HTTP2HeaderTableField("content-type", ""),
		HTTP2HeaderTableField("cookie", ""),
		HTTP2HeaderTableField("date", ""),
		HTTP2HeaderTableField("etag", ""),
		HTTP2HeaderTableField("expect", ""),
		HTTP2HeaderTableField("expires", ""),
		HTTP2HeaderTableField("from", ""),
		HTTP2HeaderTableField("host", ""),
		HTTP2HeaderTableField("if-match", ""),
		HTTP2HeaderTableField("if-modified-since", ""),
		HTTP2HeaderTableField("if-none-match", ""),
		HTTP2HeaderTableField("if-range", ""),
		HTTP2HeaderTableField("if-unmodified-since", ""),
		HTTP2HeaderTableField("last-modified", ""),
		HTTP2HeaderTableField("link", ""),
		HTTP2HeaderTableField("location", ""),
		HTTP2HeaderTableField("max-forwards", ""),
		HTTP2HeaderTableField("proxy-authenticate", ""),
		HTTP2HeaderTableField("proxy-authorization", ""),
		HTTP2HeaderTableField("range", ""),
		HTTP2HeaderTableField("referer", ""),
		HTTP2HeaderTableField("refresh", ""),
		HTTP2HeaderTableField("retry-after", ""),
		HTTP2HeaderTableField("server", ""),
		HTTP2HeaderTableField("set-cookie", ""),
		HTTP2HeaderTableField("strict-transport-security", ""),
		HTTP2HeaderTableField("transfer-encoding", ""),
		HTTP2HeaderTableField("user-agent", ""),
		HTTP2HeaderTableField("vary", ""),
		HTTP2HeaderTableField("via", ""),
		HTTP2HeaderTableField("www-authenticate", "")
	];
}

private ref immutable(HTTP2HeaderTableField) getStaticTableEntry(size_t key) @safe @nogc
{
    assert(key > 0 && key < StaticTable.length, "Invalid static table index");
    return StaticTable[key];
}

// compute size of an entry as per RFC
HTTP2SettingValue computeEntrySize(HTTP2HeaderTableField f) @safe
{
	alias k = HTTP2HeaderTableField.value.Kind;
	HTTP2SettingValue ret = cast(HTTP2SettingValue)f.name.length + 32;

	final switch (f.value.kind) {
		case k.str: ret += f.value.get!string.length; break;
		case k.strarr: ret += f.value.get!(string[]).map!(s => s.length).sum(); break;
		case k.status: ret += cast(size_t)log10(cast(int)f.value.get!HTTPStatus) + 1; break;
		case k.method: ret += httpMethodString(f.value.get!HTTPMethod).length; break;
	}
	return ret;
}

private struct DynamicTable {
	private {
		// table is a circular buffer, initially empty
		FixedRingBuffer!HTTP2HeaderTableField m_table;

		// as defined in SETTINGS_HEADER_TABLE_SIZE
		HTTP2SettingValue m_maxsize;

		// current size
		size_t m_size = 0;

		// last index (table index starts from 1)
		size_t m_index = 0;
	}

	this(HTTP2SettingValue ms) @trusted
	{
		m_maxsize = ms;
		m_table.capacity = ms;
	}

	// number of elements inside dynamic table
	@property size_t size() @safe @nogc { return m_size; }

	@property size_t index() @safe @nogc { return m_index; }

	@property ref auto table() @safe @nogc { return m_table; }

	HTTP2HeaderTableField opIndex(size_t idx) @safe @nogc
	{
		assert(idx > 0 && idx <= m_index, "Invalid table index");
		return m_table[idx-1];
	}

	// insert at the head
	void insert(HTTP2HeaderTableField header) @safe
	{
		auto nsize = computeEntrySize(header);
		// ensure that the new entry does not exceed table capacity
		while(m_size + nsize > m_maxsize) {
			//logInfo("Maximum header table size exceeded"); // requires gc
			remove();
		}

		// insert
		m_table.put(header);
		m_size += nsize;
		m_index++;
	}

	// evict an entry
	void remove() @safe
	{
		assert(!m_table.empty, "Cannot remove element from empty table");
		m_size -= computeEntrySize(m_table.back);
		m_table.popFront();
		m_index--;
	}

	/** new size should be lower than the max set one
	  * after size is successfully changed, an ACK has to be sent
	  * multiple changes between two header fields are possible
	  * if multiple changes occour, only the smallest maximum size
	  * requested has to be acknowledged
	*/
	void updateSize(HTTP2SettingValue sz) @safe @nogc
	{
		m_maxsize = sz;
	}
}

unittest {
	// static table
	auto a = getStaticTableEntry(1);
	static assert(is(typeof(a) == immutable(HTTP2HeaderTableField)));
	assert(a.name == ":authority");
	assert(getStaticTableEntry(2).name == ":method" && getStaticTableEntry(2).value == HTTPMethod.GET);

	DynamicTable dt = DynamicTable(4096);
	assert(dt.size == 0);
	assert(dt.index == 0);

	// dynamic table
	import std.algorithm.comparison : equal;

	auto h = HTTP2HeaderTableField("test", "testval");
	dt.insert(h);
	assert(dt.size > 0);
	assert(dt.index == 1);
	assert(equal(dt.table[], [h]));
	assert(dt.table[].front.name == "test");
	assert(dt[dt.index].name == "test");

	dt.remove();
	assert(dt.size == 0);
	assert(dt.index == 0);
}

/** provides an unified address space through operator overloading
  * this is the only interface that will be used for the two tables
  */
struct IndexingTable {
	private {
		DynamicTable m_dynamic;
	}

	// requires the maximum size for the dynamic table
	this(HTTP2SettingValue ms) @trusted
	{
		m_dynamic = DynamicTable(ms);
	}

	@property size_t size() @safe @nogc { return STATIC_TABLE_SIZE + m_dynamic.index + 1; }

	@property bool empty() @safe @nogc { return m_dynamic.size == 0; }

	@property HTTP2HeaderTableField front() @safe { return this[0]; }

	@property void popFront() @safe
	{
		assert(!empty, "Cannot call popFront on an empty dynamic table");
		m_dynamic.remove();
	}

	// element retrieval
	HTTP2HeaderTableField opIndex(size_t idx) @safe @nogc
	{
		assert(idx > 0 && idx <= size(), "Invalid table index");

		if (idx < STATIC_TABLE_SIZE+1) return getStaticTableEntry(idx);
		else return m_dynamic[m_dynamic.index - (idx - STATIC_TABLE_SIZE) + 1];
	}

	// dollar == size
	// +1 to mantain consistency with the dollar operator
	size_t opDollar() @safe @nogc
	{
		return size();
	}

	// assignment can only be done on the dynamic table
	void insert(HTTP2HeaderTableField hf) @safe
	{
		m_dynamic.insert(hf);
	}

	// update max dynamic table size
	void updateSize(HTTP2SettingValue sz) @safe @nogc
	{
		m_dynamic.updateSize(sz);
	}
}

unittest {
	// indexing table
	IndexingTable table = IndexingTable(4096);
	assert(table[2].name == ":method" && table[2].value == HTTPMethod.GET);

	// assignment
	auto h = HTTP2HeaderTableField("test", "testval");
	table.insert(h);
	assert(table.size == STATIC_TABLE_SIZE + 2);
	assert(table[STATIC_TABLE_SIZE+1].name == "test");

	auto h2 = HTTP2HeaderTableField("test2", "testval2");
	table.insert(h2);
	assert(table.size == STATIC_TABLE_SIZE + 3);
	assert(table[STATIC_TABLE_SIZE+1].name == "test2");

	// dollar
	auto h3 = HTTP2HeaderTableField("test3", "testval3");
	table.insert(h3);
	assert(table.size == STATIC_TABLE_SIZE + 4);
	assert(table[$-1].name == "test");
	assert(table[$-2].name == "test2");
	assert(table[STATIC_TABLE_SIZE+1].name == "test3");

	// test removal on full table
	HTTP2SettingValue hts = computeEntrySize(h); // only one header
	IndexingTable t2 = IndexingTable(hts);
	t2.insert(h);
	t2.insert(h);
	assert(t2.size == STATIC_TABLE_SIZE + 2);
	assert(t2[STATIC_TABLE_SIZE + 1].name == "test");
	assert(t2[$ - 1].name == "test");
}
