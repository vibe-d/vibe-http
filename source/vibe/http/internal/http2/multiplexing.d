module vibe.http.internal.http2.multiplexing;

import vibe.container.hashmap;
import vibe.container.internal.utilallocator;
import vibe.core.sync;
import vibe.core.log;
import vibe.core.net;
import vibe.core.core : yield;

import std.exception;
import std.container : RedBlackTree;

/* Stream multiplexing in HTTP/2
	References: https://tools.ietf.org/html/rfc7540#section-5
	The purposes of stream registration into a multiplexer are the following:
	1. Check correctness of HTTP/2 frames received, following the rules defined
	   in the HTTP/2 RFC (https://tools.ietf.org/html/rfc7540)
	2. Implement stream prioritization / dependency:
	   https://tools.ietf.org/html/rfc7540#section-5.3
	3. Hold data structures which are supposed to mantain the state of a connection,
	   since HTTP/2 opens only 1 tcp connection on which multiple frames can be sent.
*/

/* ======================================================= */
/* ================ STREAM MANAGEMENT =================== */
/* ======================================================= */

/// register a stream on a MUX
auto registerStream(Mux)(ref Mux multiplexer, const uint sid) @trusted
{
	return multiplexer.register(sid);
}

/// close a stream on a MUX
auto closeStream(Mux)(ref Mux multiplexer, const uint sid) @trusted
{
	return multiplexer.close(sid);
}

/// check if stream is OPEN (meaning, currently registered and active)
auto isOpenStream(Mux)(ref Mux multiplexer, const uint sid) @trusted
{
	return multiplexer.isOpen(sid);
}

/// connection preface (SETTINGS) can be received only ONCE
auto isConnectionPreface(Mux)(ref Mux multiplexer) @trusted
{
	return multiplexer.isConnPreface();
}

/* ======================================================= */
/* ================= FLOW CONTROL ======================== */
/* ======================================================= */

/** Per-connection window

	Valid for EVERY stream in MUX[idx]
*/
auto connectionWindow(Mux)(ref Mux multiplexer) @trusted
{
	return multiplexer.connWindow;
}

/// Update the connection window value
auto updateConnectionWindow(Mux)(ref Mux multiplexer, const ulong newWin) @trusted
{
	return multiplexer.updateConnWindow(newWin);
}

/** Per-stream window

	Valid for stream `sid` in MUX[idx]
*/
auto streamConnectionWindow(Mux)(ref Mux multiplexer, const uint sid) @trusted
{
	return multiplexer.streamConnWindow(sid);
}

/// Update the stream connection window value
auto updateStreamConnectionWindow(Mux)(ref Mux multiplexer, const uint sid, const ulong newWin) @trusted
{
	return multiplexer.updateStreamConnWindow(sid, newWin);
}

/** A TaskCondition is used to synchronize DATA frame sending

	this enforces flow control on every outgoing DATA frame
	So that the client-established connection/stream window
	is not exceeded.
	Each connection (MUX) has its own condition.
*/
void waitCondition(Mux)(ref Mux multiplexer, const uint sid) @trusted
{
	multiplexer.wait(sid);
}

/// signal the waiting task(s) that a change
/// in the connection window has occourred
void notifyCondition(Mux)(ref Mux multiplexer) @trusted
{
	multiplexer.notify();
}

/// check if waiting tasks are enqueued for this connection
uint checkCondition(Mux)(ref Mux multiplexer, const uint sid) @trusted
{
	return multiplexer.checkCond(sid);
}

/// signal that the DATA dispatch is over
/// task is no longer enqueued
void doneCondition(Mux)(ref Mux multiplexer, const uint sid) @trusted
{
	multiplexer.endWait(sid);
}

/** Underlying multiplexer data structure

	Uses a TaskMutex to perform sensitive operations
	since multiple streams might be operating on the same
	connection (MUX)
*/
struct HTTP2Multiplexer {
	/// used to register open streams, which must be unique
	private alias H2Queue = RedBlackTree!uint;

	private {
		IAllocator m_alloc;
		H2Queue m_open; // set of open streams
		uint m_closed; // index of the last closed stream
		uint m_last; // index of last open stream
		uint m_max; // maximum number of streams open at the same time
		uint m_countOpen; // current number of open streams (in m_open)
		TaskMutex m_lock;
		TaskCondition m_cond;
		uint[uint] m_waiting;
		ulong m_wsize;
		ulong[uint] m_streamWSize;
		bool m_connPreface = true;
	}

	@disable this();

	this(Alloc)(Alloc alloc, const uint max, const ulong wsize, const uint tsize = 4096) @trusted
	nothrow
	{
		m_alloc = alloc;
		try {
			m_lock = alloc.make!TaskMutex();
			m_cond = alloc.make!TaskCondition(m_lock);
			m_open = alloc.make!H2Queue();
		} catch (Exception e)
			assert(false, e.msg);
		m_last = 0;
		m_max = max;
		m_wsize = wsize;
	}

	/*
		The methods from here downwards
		are not supposed to be used directly,
		but through the documented wrappers above.
	*/
	@property void wait(const uint sid) @trusted
	{
		synchronized (m_lock) {
			if (!(sid in m_waiting))
				m_waiting[sid] = 0;
			else
				m_waiting[sid]++;
			m_cond.wait();
		}
	}

	@property void endWait(const uint sid) @trusted
	{
		synchronized (m_lock) {
			if (!(sid in m_waiting))
				m_waiting[sid] = 0;
			else
				m_waiting[sid]--;
		}
	}

	@property void notify() @trusted
	{
		m_cond.notify();
	}

	@property uint checkCond(const uint sid) @safe
	{
		if (!(sid in m_waiting))
			return 0;
		return m_waiting[sid] > 0 && isOpen(sid);
	}

	@property ulong connWindow() @safe
	{
		return m_wsize;
	}

	@property ulong streamConnWindow(const uint sid) @safe
	{
		if (!(sid in m_streamWSize))
			return 0;

		return m_streamWSize[sid];
	}

	@property bool isConnPreface() @safe
	{
		// can only be true once per connection
		auto b = m_connPreface;

		m_lock.performLocked!({ m_connPreface = false; });

		return b;
	}

	// register a new open stream
	bool register(const uint sid) @safe
	{
		if (sid == 0)
			return true; // success, but sid=0 is not registered
		if (m_countOpen + 1 > m_max)
			return false; // PROTOCOL_ERROR: too many open streams
		if (sid <= m_last && sid != 0)
			return false; // Stream ID must be greater than previously
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
		if (!(sid in m_open))
			return false; //Cannot close a stream which is not open
		if (sid in m_waiting && m_waiting[sid])
			return false; //Cannot close a stream which is blocked

		m_lock.performLocked!({
			m_countOpen--;
			m_open.removeKey(sid);
			m_streamWSize.remove(sid);
		});
		return true;
	}

	// open streams are present in m_open
	bool isOpen(const uint sid) @safe
	{
		return sid in m_open;
	}

	bool updateConnWindow(const ulong newWin) @safe
	{
		if (newWin > ulong.max || newWin < 0)
			return false;
		logDebug("MUX: CONTROL FLOW WINDOW: from %d to %d bytes", m_wsize, newWin);

		m_lock.performLocked!({ m_wsize = newWin; });

		return true;
	}

	bool updateStreamConnWindow(const uint sid, const ulong newWin) @safe
	{
		if (newWin > ulong.max || newWin < 0)
			return false;
		if (sid == 0)
			return true;

		logDebug("MUX: CONTROL FLOW WINDOW: stream %d from %d to %d bytes",
			sid, (sid in m_streamWSize) ? m_streamWSize[sid] : m_wsize, newWin);

		m_lock.performLocked!({ m_streamWSize[sid] = newWin; });

		return true;
	}

}
