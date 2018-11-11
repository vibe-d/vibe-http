module vibe.http.internal.http2.frame;

import std.typecons;
import std.traits;
import std.range;
import std.algorithm.iteration;


/** This module implements HTTP/2 Frames, as defined in RFC 7540 under:
  *
  * Section 4: Frame overview, Frame header composition (octets) and their meaning
  * https://tools.ietf.org/html/rfc7540#section-4
  *
  * Section 6: Frame definition according to Frame Type
  * https://tools.ietf.org/html/rfc7540#section-6
*/

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

/// utility function : packing
void createHTTP2FrameHeader(R)(ref R dst, const uint len, const HTTP2FrameType type, const ubyte flags, const uint sid) @safe @nogc
{
	dst.serialize(HTTP2FrameHeader(len, type, flags, sid));
}

/// utility function : serializing
void serializeHTTP2FrameHeader(R)(ref R dst, HTTP2FrameHeader header) @safe @nogc
{
	dst.serialize(header);
}

/// utility function : unpacking
HTTP2FrameHeader unpackHTTP2FrameHeader(R)(ref R src) @safe @nogc
	if(is(ElementType!R : ubyte))
{
	return HTTP2FrameHeader(src);
}

/** Implement an HTTP/2 Frame header
  * The header is a 9-bit ubyte[9] string
  */
struct HTTP2FrameHeader
{
	private {
		ubyte[3] length; 	// 24-bit frame payload length
		HTTP2FrameType type; 		// frame type (stored as ubyte for serialization)
		ubyte flags; 		// frame flags
		ubyte[4] streamId;  // stream id, uint (stored as ubyte for serialization)
	}

	this(const uint len, const HTTP2FrameType tp, const ubyte flg, const uint sid) @safe @nogc
	{
		assert(sid < (cast(ulong)1 << 32), "Invalid stream id");
		length.putBytes!(3, ubyte)(len);
		type = tp;
		flags = flg;
		streamId.putBytes!(4, ubyte)(sid & ((cast(ulong)1 << 32) - 1)); // reserved bit is 0
	}

	this(const ubyte[] src) @safe @nogc
	{
		assert(src.length >= 9, "Invalid serialized frame header");
		length = src[0..3];
		type = cast(HTTP2FrameType)src[3];
		flags = src[4];
		streamId = src[5..9];
	}
}

/// convert 32-bit unsigned integer to N-bit ubyte[N]
private void putBytes(uint N, R)(ref R[N] dst, const(ulong) src) @safe @nogc
{
	assert(src > 0 && src < (cast(ulong)1 << N*8), "Invalid frame payload length");
	assert(dst.length >= N);

	foreach(i,ref b; dst[0..N]) b = cast(ubyte)(src >> 8*i) & 0xff;
}

/// fill a buffer / appender with fields from `header`
private void serialize(R)(ref R dst, HTTP2FrameHeader header) @safe @nogc
	if(hasLength!R && isOutputRange!(R, ubyte))
{
	assert(dst.length >= 9, "Output range has not enough space for this header");

	static foreach(f; __traits(allMembers, HTTP2FrameHeader)) {
		static if(f != "__ctor") {
			static if(isArray!(typeof(__traits(getMember, HTTP2FrameHeader, f)))) {
				mixin("foreach(b; header."~f~") dst.put(b);");
			} else {
				static if(f == "type") mixin("dst.put(cast(ubyte)header."~f~");");
				else mixin("dst.put(header."~f~");");
			}
		}
	}
}

unittest {
	import vibe.internal.array : BatchBuffer;

	auto header = HTTP2FrameHeader(451, cast(HTTP2FrameType)1, 0, 123485);
	ubyte[9] expected = [195, 1, 0, 1, 0, 93, 226, 1, 0];
	BatchBuffer!(ubyte, 9) dst;
	dst.putN(9);
	// serialize to a ubyte[9] array
	serialize(dst,header);
	assert(dst.peekDst == expected);
	assert(HTTP2FrameHeader(dst.peekDst) == header);

	// test utility functions
	BatchBuffer!(ubyte, 9) ddst;
	ddst.putN(9);
	ddst.createHTTP2FrameHeader(451, cast(HTTP2FrameType)1, 0, 123485);
	assert(dst.peekDst == ddst.peekDst);

	BatchBuffer!(ubyte, 9) dddst;
	dddst.putN(9);
	dddst.serializeHTTP2FrameHeader(header);
	assert(dst.peekDst == dddst.peekDst);

	// test unpacking
	assert(header == unpackHTTP2FrameHeader(expected));
}
