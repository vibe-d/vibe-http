module vibe.http.internal.http2.frame;

import vibe.http.internal.http2.settings;

import std.typecons;
import std.traits;
import std.range;
import std.array;
import std.algorithm.iteration;
import std.algorithm.mutation;


/** This module implements HTTP/2 Frames, as defined in RFC 7540 under:
  *
  * Section 4: Frame overview, Frame header composition (octets) and their meaning
  * https://tools.ietf.org/html/rfc7540#section-4
  *
  * Section 6: Frame definition according to Frame Type
  * https://tools.ietf.org/html/rfc7540#section-6
*/

enum uint HTTP2HeaderLength = 9;

enum HTTP2FrameType {
	DATA 			= 0x0,
	HEADERS 		= 0x1,
	PRIORITY 		= 0x2,
	RST_STREAM 		= 0x3,
	SETTINGS 		= 0x4,
	PUSH_PROMISE 	= 0x5,
	PING 			= 0x6,
	GOAWAY 			= 0x7,
	WINDOW_UPDATE 	= 0x8,
	CONTINUATION 	= 0x9
}

/*** FRAME PARSING ***/

/// updated by `unpackHTTP2Frame`
struct HTTP2FrameStreamDependency {
	bool exclusive = false;
	bool isPushPromise = false;
	uint streamId = 0;
	ubyte weight = 0;

	@property bool isSet() @safe @nogc { return streamId != 0; }

	void fill(R)(ref R src) @safe @nogc
		if(is(ElementType!R : ubyte))
	{
		uint first = src.takeExactly(4).fromBytes(4);
		exclusive = first & (cast(ulong)1 << 32);
		streamId = first & ((cast(ulong)1 << 32) - 1);
		src.popFrontN(4);

		if(!isPushPromise) {
			weight = src.front;
			src.popFront();
		}
	}
}

/// DITTO
HTTP2FrameHeader unpackHTTP2Frame(R,T)(ref R payloadDst, T src, ref bool endStream, ref bool needsCont, ref bool ack, ref HTTP2FrameStreamDependency sdep) @safe
{
	auto header = unpackHTTP2FrameHeader(src);
	unpackHTTP2Frame(payloadDst, src, header, endStream, needsCont, ack, sdep);
	return header;
}

/** unpacks a frame putting the payload in `payloadDst` and returning the header
  * implements the checks required for each frame type (Section 6 of HTTP/2 RFC)
  *
  * Invoked by a possible HTTP/2 request handler, the payload is meant to be handled by
  * the caller.
  *
  * Note: @nogc-compatible as long as payloadDst.put is @nogc (AllocAppender.put isn't)
  */
void unpackHTTP2Frame(R,T)(ref R payloadDst, ref T src, HTTP2FrameHeader header, ref bool endStream, ref bool needsCont, ref bool ack, ref HTTP2FrameStreamDependency sdep) @safe
{
	size_t len = header.payloadLength;

	switch(header.type) {
		case HTTP2FrameType.DATA:
			if(header.flags & 0x8) { // padding is set, first bit is pad length
				len -= cast(size_t)src.front;
				src.popFront();
			}
			foreach(b; src.takeExactly(len)) {
				payloadDst.put(b);
				src.popFront();
			}
			src.popFrontN(header.payloadLength - len); // remove padding
			if(header.flags & 0x1) endStream = true;
			break;

		case HTTP2FrameType.HEADERS:
			if(header.flags & 0x8) { // padding is set, first bit is pad length
				len -= cast(size_t)src.front;
				src.popFront();
			}
			if(header.flags & 0x20) { // priority is set, fill `sdep`
				sdep.fill(src);
				len -= 5;
			}
			foreach(b; src.takeExactly(len)) {
				payloadDst.put(b);
				src.popFront();
			}
			src.popFrontN(header.payloadLength - len); // remove padding
			if(header.flags & 0x1) endStream = true;
			if(!(header.flags & 0x4)) needsCont = true;
			break;

		case HTTP2FrameType.PRIORITY:
			assert(len == 5, "Invalid PRIORITY Frame");
			sdep.fill(src);
			break;

		case HTTP2FrameType.RST_STREAM:
			assert(len == 4, "Invalid RST_STREAM Frame");
			foreach(b; src.takeExactly(len)) {
				payloadDst.put(b);
				src.popFront();
			}
			break;

		case HTTP2FrameType.SETTINGS:
			assert(len % 6 == 0, "Invalid SETTINGS Frame (FRAME_SIZE error)");
			assert(header.streamId == 0, "Invalid streamId for SETTINGS Frame");
			if(header.flags & 0x1) { // this is an ACK frame
				assert(len == 0, "Invalid SETTINGS ACK Frame (FRAME_SIZE error)");
				ack = true;
				break;
			}
			foreach(b; src.takeExactly(len)) {
				payloadDst.put(b);
				src.popFront();
			}
			break;

		case HTTP2FrameType.PUSH_PROMISE:
			if(header.flags & 0x8) { // padding is set, first bit is pad length
				len -= cast(size_t)src.front;
				src.popFront();
			}
			sdep.isPushPromise = true;
			sdep.fill(src);
			len -= 4;
			foreach(b; src.takeExactly(len)) {
				payloadDst.put(b);
				src.popFront();
			}
			src.popFrontN(header.payloadLength - len); // remove padding
			if(!(header.flags & 0x4)) needsCont = true;
			break;

		case HTTP2FrameType.PING:
			assert(len == 8, "Invalid PING Frame (FRAME_SIZE error)");
			assert(header.streamId == 0, "Invalid streamId for PING Frame");
			if(header.flags & 0x1) {
				ack = true;
			}
			foreach(b; src.takeExactly(len)) {
				payloadDst.put(b);
				src.popFront();
			}
			break;

		case HTTP2FrameType.GOAWAY: // GOAWAY is used to close connection (in handler)
			assert(len >= 8, "Invalid GOAWAY Frame (FRAME_SIZE error)");
			assert(header.streamId == 0, "Invalid streamId for GOAWAY Frame");
			foreach(b; src.takeExactly(len)) {
				payloadDst.put(b);
				src.popFront();
			}
			break;

		case HTTP2FrameType.WINDOW_UPDATE:
			assert(len == 4, "Invalid WINDOW_UPDATE Frame (FRAME_SIZE error)");
			foreach(i,b; src.takeExactly(len).enumerate) {
				if(i == 0) b &= 127; // reserved bit
				payloadDst.put(b);
				src.popFront();
			}
			break;

		case HTTP2FrameType.CONTINUATION:
			assert(header.streamId != 0, "Invalid streamId for CONTINUATION frame");
			foreach(b; src.takeExactly(len)) {
				payloadDst.put(b);
				src.popFront();
			}
			if(!(header.flags & 0x4)) needsCont = true;
			break;

		default:
			assert(false, "Invalid frame header unpacked");
	}
}

unittest {
	import vibe.internal.array : FixedAppender;

	FixedAppender!(ubyte[], 4) payloadDst;
	bool endStream = false;
	bool needsCont = false;
	bool ack = false;
	HTTP2FrameStreamDependency sdep;


	// DATA Frame
	ubyte[] data = [0, 0, 4, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1];
	payloadDst.unpackHTTP2Frame(data, endStream, needsCont, ack, sdep);
	assert(payloadDst.data == [1, 1, 1, 1]);

	// HEADERS Frame
	payloadDst.clear;
	data = [0, 0, 4, 1, 0, 0, 0, 0, 2, 2, 2, 2, 2];
	payloadDst.unpackHTTP2Frame(data, endStream, needsCont, ack, sdep);
	assert(payloadDst.data == [2, 2, 2, 2]);

	// PRIORITY Frame
	payloadDst.clear;
	data = [0, 0, 5, 2, 0, 0, 0, 0, 3, 0, 0, 0, 2, 5];
	payloadDst.unpackHTTP2Frame(data, endStream, needsCont, ack, sdep);
	assert(payloadDst.data == []);
	assert(sdep.weight == 5 &&  sdep.streamId == 2);

	// RST_STREAM Frame
	payloadDst.clear;
	data = [0, 0, 4, 3, 0, 0, 0, 0, 4, 4, 4, 4, 4];
	payloadDst.unpackHTTP2Frame(data, endStream, needsCont, ack, sdep);
	assert(payloadDst.data == [4, 4, 4, 4]);

	// SETTINGS Frame
	FixedAppender!(ubyte[], 6) settingsDst;
	data = [0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 1, 2, 2, 2, 2];
	settingsDst.unpackHTTP2Frame(data, endStream, needsCont, ack, sdep);
	assert(settingsDst.data == [0, 1, 2, 2, 2, 2]);

	// PUSH_PROMISE Frame
	payloadDst.clear;
	data = [0, 0, 8, 5, 0, 0, 0, 0, 5, 0, 0, 0, 2, 4, 4, 4, 4];
	payloadDst.unpackHTTP2Frame(data, endStream, needsCont, ack, sdep);
	assert(payloadDst.data == [4, 4, 4, 4]);
	assert(sdep.weight == 5 &&  sdep.streamId == 2);

	// PING Frame
	FixedAppender!(ubyte[], 8) pingDst;
	data = [0, 0, 8, 6, 0, 0, 0, 0, 0, 0, 0, 0, 2, 4, 4, 4, 4];
	pingDst.unpackHTTP2Frame(data, endStream, needsCont, ack, sdep);
	assert(pingDst.data == [0, 0, 0, 2, 4, 4, 4, 4]);

	// GOAWAY Frame
	pingDst.clear;
	data = [0, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 4];
	pingDst.unpackHTTP2Frame(data, endStream, needsCont, ack, sdep);
	assert(pingDst.data == [0, 0, 0, 2, 0, 0, 0, 4]);

	// WINDOW_UPDATE
	payloadDst.clear;
	data = [0, 0, 4, 8, 0, 0, 0, 0, 6, 1, 1, 1, 1];
	payloadDst.unpackHTTP2Frame(data, endStream, needsCont, ack, sdep);
	assert(payloadDst.data == [1, 1, 1, 1]);

	// CONTINUATION
	payloadDst.clear;
	data = [0, 0, 4, 9, 0, 0, 0, 0, 6, 2, 2, 2, 2];
	payloadDst.unpackHTTP2Frame(data, endStream, needsCont, ack, sdep);
	assert(payloadDst.data == [2, 2, 2, 2]);
}

/*** FRAME BUILDING ***/

/// concatenates a Frame header with a Frame payload
void buildHTTP2Frame(R,H,T)(ref R dst, ref H header, ref T payload) @safe @nogc
	if(is(ElementType!R : ubyte) && is(ElementType!T : ubyte))
{
	// put header
	static if(is(H == HTTP2FrameHeader)) {
		assert(header.payloadLength == payload.length, "Invalid payload length");
		dst.serializeHTTP2FrameHeader(header);

	} else static if(is(ElementType!H : ubyte)) {
		auto len = header.takeExactly(3).fromBytes(3);
		assert(len == payload.length, "Invalid payload length");
		foreach(b; header) dst.put(b);
	}

	// put payload
	foreach(b; payload) dst.put(b);
}

/// DITTO
/// @nogc-compatible if dst.put is @nogc
void buildHTTP2Frame(R,T)(ref R dst, T payload) @safe
{
	// put payload
	foreach(b; payload) dst.put(b);
}

unittest {
	import vibe.internal.array : BatchBuffer;

	auto header = HTTP2FrameHeader(4, cast(HTTP2FrameType)1, 0, 5);
	ubyte[4] payload = [0, 1, 2, 3];
	ubyte[] bheader = [0, 0, 4, 1, 0, 0, 0, 0, 5];
	ubyte[13] expected = [0, 0, 4, 1, 0, 0, 0, 0, 5, 0, 1, 2, 3];

	BatchBuffer!(ubyte, 13) dst, ddst;
	dst.putN(13);
	ddst.putN(13);
	dst.buildHTTP2Frame(header, payload);
	ddst.buildHTTP2Frame(bheader, payload);

	assert(dst.peekDst == expected);
	assert(ddst.peekDst == expected);
}

/*** FRAME HEADER ***/
/// header packing
/// @nogc-compatible if dst.put is @nogc
void createHTTP2FrameHeader(R)(ref R dst, const uint len, const HTTP2FrameType type, const ubyte flags, const uint sid) @safe
{
	dst.serialize(HTTP2FrameHeader(len, type, flags, sid));
}

/// serializing
void serializeHTTP2FrameHeader(R)(ref R dst, HTTP2FrameHeader header) @safe @nogc
{
	dst.serialize(header);
}

/// unpacking
HTTP2FrameHeader unpackHTTP2FrameHeader(R)(ref R src) @safe @nogc
{
	HTTP2FrameHeader header = void;

	static if(isStaticArray!R) {
		import vibe.internal.array : BatchBuffer;
		BatchBuffer!(ubyte, 9) bbuf;
		bbuf.putN(src);
		header = HTTP2FrameHeader(bbuf);
	} else {
		header = HTTP2FrameHeader(src);
	}

	return header;
}

/** Implement an HTTP/2 Frame header
  * The header is a 9-bit ubyte[9] string
  */
struct HTTP2FrameHeader
{
	private {
		ubyte[3] m_length; 			// 24-bit frame payload length
		HTTP2FrameType m_type; 		// frame type (stored as ubyte for serialization)
		ubyte m_flags; 				// frame flags
		ubyte[4] m_streamId;  		// stream id, uint (stored as ubyte for serialization)
	}

	this(const uint len, const HTTP2FrameType tp, const ubyte flg, const uint sid) @safe @nogc
	{
		assert(sid < (cast(ulong)1 << 32), "Invalid stream id");
		m_length.putBytes!(3)(len);
		m_type = tp;
		m_flags = flg;
		m_streamId.putBytes!(4)(sid & ((cast(ulong)1 << 32) - 1)); // reserved bit is 0
	}

	this(T)(ref T src) @safe @nogc
		if(is(ElementType!T : ubyte))
	{
		foreach(i,b; src.take(3).enumerate) {
			m_length[i] = b;
			src.popFront();
		}

		m_type = cast(HTTP2FrameType)src.front; src.popFront;
		m_flags = src.front; src.popFront;

		foreach(i,b; src.take(4).enumerate) {
			m_streamId[i] = b;
			src.popFront();
		}
	}

	@property HTTP2FrameType type() @safe @nogc { return m_type; }

	@property uint payloadLength() @safe @nogc { return m_length.fromBytes(3); }

	@property ubyte flags() @safe @nogc { return m_flags; }

	@property uint streamId() @safe @nogc { return m_streamId.fromBytes(4); }
}

/// convert 32-bit unsigned integer to N bytes (MSB first)
void putBytes(uint N, R)(ref R dst, const(ulong) src) @safe @nogc
{
	assert(src >= 0 && src < (cast(ulong)1 << N*8), "Invalid frame payload length");
	static if(hasLength!R) assert(dst.length >= N);

	ubyte[N] buf;
	foreach(i,ref b; buf) b = cast(ubyte)(src >> 8*(N-1-i)) & 0xff;

	static if(isArray!R) {
		dst = buf;
	} else {
		foreach(b; buf) dst.put(b);
	}
}

/// convert a N-bytes representation MSB->LSB to uint
uint fromBytes(R)(R src, uint n) @safe @nogc
{
	uint res = 0;
	static if(isArray!R) {
		foreach(i,b; src) res = res + (b << 8*(n-1-i));
	} else {
		foreach(i,b; src.enumerate.retro) res = res + (b << 8*i);
	}
	return res;
}

/// fill a buffer with fields from `header`
/// @nogc-compatible if dst.put is @nogc
private void serialize(R)(ref R dst, HTTP2FrameHeader header) @safe
	if(isOutputRange!(R, ubyte))
{
	static foreach(f; __traits(allMembers, HTTP2FrameHeader)) {
		static if(f != "__ctor" && f != "type"
				&& f != "payloadLength" && f != "flags" && f != "streamId") {
			static if(isArray!(typeof(__traits(getMember, HTTP2FrameHeader, f)))) {
				mixin("foreach(b; header."~f~") dst.put(b);");
			} else static if(f == "m_type") {
				mixin("dst.put(cast(ubyte)header."~f~");");
			} else {
				mixin("dst.put(header."~f~");");
			}
		}
	}
}

unittest {
	import vibe.internal.array : FixedAppender;

	auto header = HTTP2FrameHeader(2, cast(HTTP2FrameType)1, 0, 5);
	ubyte[] expected = [0, 0, 2, 1, 0, 0, 0, 0, 5];
	FixedAppender!(ubyte[], 9) dst;
	// serialize to a ubyte[9] array
	serialize(dst,header);
	assert(dst.data == expected);

	// test utility functions
	FixedAppender!(ubyte[], 9) ddst;
	ddst.createHTTP2FrameHeader(2, cast(HTTP2FrameType)1, 0, 5);
	assert(dst.data == ddst.data);

	FixedAppender!(ubyte[], 9) dddst;
	dddst.serializeHTTP2FrameHeader(header);
	assert(dst.data == dddst.data);

	// test unpacking
	assert(header == unpackHTTP2FrameHeader(expected));

	assert(header.payloadLength == 2);
}

