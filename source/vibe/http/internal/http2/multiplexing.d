module vibe.http.internal.http2.multiplexing;

import vibe.http.internal.http2.hpack.tables;

import vibe.utils.array : ArraySet;
import vibe.core.sync;
import vibe.core.log;
import vibe.core.concurrency : async;
import vibe.internal.allocator;
import vibe.internal.utilallocator: RegionListAllocator;


/** Stream multiplexing in HTTP/2
  * References: https://tools.ietf.org/html/rfc7540#section-5
  *
  * The purposes of stream registration into a multiplexer are the following:
  * 1. Check correctness of HTTP/2 frames received, following the rules defined
  *    in the HTTP/2 RFC (https://tools.ietf.org/html/rfc7540)
  * 2. Implement stream prioritization / dependency:
  *    https://tools.ietf.org/html/rfc7540#section-5.3
  * 3. Hold data structures which are supposed to mantain the state of a connection,
  *	   since HTTP/2 opens only 1 tcp connection on which multiple frames can be sent.
*/

private {
	__gshared HTTP2Multiplexer[string] multiplexers;
	//__gshared IndexingTable[string] tables;
}

// init the multiplexer
void multiplexer(const string id, const uint max, const uint tsize=4096) @trusted
{
	logWarn("Initializing multiplexer with id: "~id);

	assert(!(id in multiplexers));

	version (VibeManualMemoryManagement)
		scope alloc = new RegionListAllocator!(shared(Mallocator), false)
						(1024, Mallocator.instance);
	else
		scope alloc = new RegionListAllocator!(shared(GCAllocator), true)
						(1024, GCAllocator.instance);

	multiplexers[id] = HTTP2Multiplexer(alloc, max, tsize);
}

void removeMux(const string idx) @trusted
{
	logWarn("Removing multiplexer with id: "~idx);
	multiplexers.remove(idx);
}

// register a stream ID
auto registerStream(const string idx, const uint sid) @trusted
{
	import std.conv : to;
	if(sid > 0) logWarn("MUX: Registering stream " ~ sid.to!string ~ " on mux["~idx~"]");
	return async({
			return multiplexers[idx].register(sid);
		});
}

// close a stream ID
auto closeStream(const string idx, const uint sid) @trusted
{
	import std.conv : to;
	if(sid > 0) logWarn("MUX: Closing stream " ~ sid.to!string ~ " on mux["~idx~"]");
	return async({
			return multiplexers[idx].close(sid);
		});
}

//IndexingTable getTable(const string idx) @trusted
//{
	//return tables[idx];
//}

//void leaveTable(const string idx) @trusted
//{
	//assert(multiplexers[idx].tableLocked == true);
	//multiplexers[idx].unlockTable();
//}

unittest {
	string id = "localhost:80";
	multiplexer(id, 2);

	auto reg = registerStream(id, 1);
	assert(reg.getResult);
	auto cls = closeStream(id, 1);

	assert(multiplexers.length == 1);
	assert(cls.getResult);

	id.removeMux();
	assert(multiplexers.length == 0);
}

private alias H2Queue = ArraySet!uint;

struct HTTP2Multiplexer {
	private {
		H2Queue m_open;		// buffer of open streams
		uint m_closed;		// index of the last closed stream
		uint m_last;		// index of last open stream
		uint m_max;			// maximum number of streams open at the same time
		uint m_countOpen;   // current number of open streams (in m_open)
		TaskMutex m_lock;
	}

	this(Alloc)(Alloc alloc, const uint max, const uint tsize=4096) @trusted
	{
		m_lock = new TaskMutex;
		m_open.setAllocator(alloc);
		m_last = 0;
		m_max = max;
	}

	// register a new open stream
	bool register(const uint sid) @safe
	{
		if(sid == 0) return true; 					// success, but sid=0 is not registered
		if(m_countOpen + 1 > m_max) return false; 	// PROTOCOL_ERROR: too many open streams
		if(sid <= m_last && sid != 0) return false; // Stream ID must be greater than previously
													// registered ones
		m_lock.performLocked!({
			m_countOpen++;
			m_open.insert(sid);
			m_last = sid;
		});
		return true;
	}

	// close an open stream
	bool close(const uint sid) @safe
	{
		if(!m_open.contains(sid)) return false; //Cannot close a stream which is not open

		m_lock.performLocked!({
			m_countOpen--;
			m_open.remove(sid);
		});
		return true;
	}
}
