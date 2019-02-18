module vibe.http.internal.http2.error;

import vibe.http.internal.http2.hpack.exception;
import vibe.http.internal.http2.frame;

import vibe.core.log;
import vibe.core.net;
import vibe.core.core;
import vibe.core.stream;
import vibe.stream.tls;
import vibe.internal.array;
import vibe.internal.allocator;
import vibe.internal.freelistref;
import vibe.internal.interfaceproxy;

import std.range;
import std.base64;
import std.traits;
import std.bitmanip; // read from ubyte (decoding)
import std.typecons;
import std.conv : to;
import std.exception : enforce;
import std.algorithm : canFind; // alpn callback
import std.algorithm.iteration;
import std.variant : Algebraic;

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
@safe @nogc
{
	assert(buf.length == GOAWAYFrameLength, "Unable to create GOAWAY frame");

	buf.createHTTP2FrameHeader(8, HTTP2FrameType.GOAWAY, 0x0, 0x0);
	buf.putBytes!4(streamId & 127); // last stream ID
	buf.putBytes!4(error);
}
