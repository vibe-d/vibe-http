module vibe.http.internal.http2.error;

import vibe.http.internal.http2.hpack.exception;
import vibe.http.internal.http2.frame;

import vibe.container.internal.utilallocator;
import vibe.core.log;
import vibe.core.net;
import vibe.core.core;
import vibe.core.stream;
import vibe.stream.tls;
import vibe.internal.array;
import vibe.internal.freelistref;
import vibe.internal.interfaceproxy;

import std.range;
import std.base64;
import std.traits;
import std.bitmanip; // read from ubyte (decoding)
import std.typecons;
import std.conv : to;
import std.exception;
import std.algorithm : canFind; // alpn callback
import std.algorithm.iteration;

enum HTTP2Error {
	NO_ERROR 			= 0x0,
	PROTOCOL_ERROR 		= 0x1,
	INTERNAL_ERROR 		= 0x2,
	FLOW_CONTROL_ERROR 	= 0x3,
	SETTINGS_TIMEOUT 	= 0x4,
	STREAM_CLOSED 		= 0x5,
	FRAME_SIZE_ERROR 	= 0x6,
	REFUSED_STREAM 		= 0x7,
	CANCEL 				= 0x8,
	COMPRESSION_ERROR 	= 0x9,
	CONNECT_ERROR 		= 0xa,
	ENHANCE_YOUR_CALM 	= 0xb,
	INADEQUATE_SECURITY = 0xc,
	HTTP_1_1_REQUIRED 	= 0xd
}

enum GOAWAYFrameLength = 17;

/// creates a GOAWAY frame as defined in RFC 7540, section 6.8
void buildGOAWAYFrame(R)(ref R buf, const uint streamId, HTTP2Error error)
@safe @nogc if (isOutputRange!(R, ubyte))
{
	assert(buf.length == GOAWAYFrameLength, "Unable to create GOAWAY frame");

	// last stream processed by the server (client-initiated)
	uint sid = (streamId > 1) ? streamId - 2 : 0;

	buf.createHTTP2FrameHeader(8, HTTP2FrameType.GOAWAY, 0x0, 0x0);
	buf.putBytes!4(sid & 127); // last stream ID
	buf.putBytes!4(error);
}
/// ditto
void buildGOAWAYFrame(ref ubyte[GOAWAYFrameLength] dst, uint sid, HTTP2Error code)
@safe @nogc
{
	dst[].buildGOAWAYFrame(sid, code);
}

/// exceptions
T enforceHTTP2(T)(T condition, string message = null, HTTP2Error h2e = HTTP2Error.NO_ERROR, string file = __FILE__, typeof(
		__LINE__) line = __LINE__) @trusted
{
	return enforce(condition, new HTTP2Exception(message, h2e, file, line));
}

class HTTP2Exception : Exception {
	HTTP2Error code;

	this(string msg, HTTP2Error h2e = HTTP2Error.NO_ERROR, string file = __FILE__, size_t line = __LINE__)
	{
		code = h2e;
		super(msg, file, line);
	}
}
