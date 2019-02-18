module vibe.http.internal.http2.multiplexing;


import vibe.utils.array : ArraySet;
import vibe.core.sync;
import vibe.core.log;
import vibe.core.net;
import vibe.core.concurrency : async;
import vibe.internal.allocator;
import vibe.internal.utilallocator: RegionListAllocator;

import std.exception;


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
}

private const string index = "auto idx = connection.peerAddress; enforce(idx != \"<UNSPEC>\",\"Unable to test stream, is the connection open?\");";

// init the multiplexer
void multiplexer(Conn)(Conn connection, const uint max, const uint wsize, const uint tsize=4096) @trusted
	if(is(Conn : TCPConnection))
{
	mixin(index);

	logWarn("Initializing multiplexer with idx: "~idx);
	assert(!(idx in multiplexers));

	version (VibeManualMemoryManagement)
		scope alloc = new RegionListAllocator!(shared(Mallocator), false)
						(1024, Mallocator.instance);
	else
		scope alloc = new RegionListAllocator!(shared(GCAllocator), true)
						(1024, GCAllocator.instance);

	multiplexers[idx] = HTTP2Multiplexer(alloc, max, wsize, tsize);
}

void removeMux(Conn)(Conn connection) @trusted
	if(is(Conn : TCPConnection))
{
	mixin(index);

	logWarn("Removing multiplexer with id: "~idx);
	multiplexers.remove(idx);
}

// register a stream ID
auto registerStream(Conn)(Conn connection, const uint sid) @trusted
	if(is(Conn : TCPConnection))
{
	mixin(index);

	if(sid > 0) logWarn("MUX: Registering stream %d on mux[%s]", sid, idx);
	return async({
			return multiplexers[idx].register(sid);
		});
}

// close a stream ID
auto closeStream(Conn)(Conn connection, const uint sid) @trusted
	if(is(Conn : TCPConnection))
{
	mixin(index);

	if(sid > 0) logWarn("MUX: Closing stream %d on mux[%s]", sid, idx);
	return async({
			return multiplexers[idx].close(sid);
		});
}

bool isOpenStream(Conn)(Conn connection, const uint sid) @trusted
	if(is(Conn : TCPConnection))
{
	mixin(index);

	return multiplexers[idx].isOpen(sid);
}

ulong connectionWindow(Conn)(Conn connection) @trusted
{
	mixin(index);

	return multiplexers[idx].connWindow;
}

bool updateConnectionWindow(Conn)(Conn connection, const ulong newWin) @trusted
{
	mixin(index);

	return async({
			return multiplexers[idx].updateConnWindow(newWin);
		});
}

ulong streamConnectionWindow(Conn)(Conn connection, const uint sid) @trusted
{
	mixin(index);

	return multiplexers[idx].streamConnWindow(sid);
}

bool updateStreamConnectionWindow(Conn)(Conn connection, const uint sid, const ulong newWin) @trusted
{
	mixin(index);

	return async({
			return multiplexers[idx].updateStreamConnWindow(sid, newWin);
		});
}
//unittest {
	//string id = "localhost:80";
	//multiplexer(id, 2);

	//auto reg = registerStream(id, 1);
	//assert(reg.getResult);
	//auto cls = closeStream(id, 1);

	//assert(multiplexers.length == 1);
	//assert(cls.getResult);

	//id.removeMux();
	//assert(multiplexers.length == 0);
//}

private alias H2Queue = ArraySet!uint;

struct HTTP2Multiplexer {
	private {
		H2Queue m_open;		// buffer of open streams
		uint m_closed;		// index of the last closed stream
		uint m_last;		// index of last open stream
		uint m_max;			// maximum number of streams open at the same time
		uint m_countOpen;   // current number of open streams (in m_open)
		TaskMutex m_lock;
		ulong m_wsize;
		ulong[uint] m_streamWSize;
	}

	this(Alloc)(Alloc alloc, const uint max, const ulong wsize, const uint tsize=4096) @trusted
	{
		m_lock = new TaskMutex;
		m_open.setAllocator(alloc);
		m_last = 0;
		m_max = max;
		m_wsize = wsize;
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
			m_streamWSize[sid] = m_wsize;
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
			m_streamWSize.remove(sid);
		});
		return true;
	}

	// open streams are present in m_open
	bool isOpen(const uint sid) @safe
	{
		return m_open.contains(sid);
	}

	@property ulong connWindow() @safe
	{
		return m_wsize;
	}

	@property ulong streamConnWindow(const uint sid) @safe
	{
		return m_streamWSize[sid];
	}

	bool updateConnWindow(const ulong newWin) @safe
	{
		if(newWin > ulong.max || newWin < 0) return false;
		logWarn("MUX: updating window size from %d to %d bytes", m_wsize, newWin);

		m_lock.performLocked!({
			m_wsize = newWin;
		});
		return true;
	}

	bool updateStreamConnWindow(const uint sid, const ulong newWin) @safe
	{
		if(newWin > ulong.max || newWin < 0) return false;
		logWarn("MUX: updating window size of stream %d from %d to %d bytes", sid, m_streamWSize[sid], newWin);

		m_lock.performLocked!({
				m_streamWSize[sid] = newWin;
		});
		return true;
	}
}
