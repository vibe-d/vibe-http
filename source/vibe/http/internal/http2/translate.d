module vibe.http.internal.http2.translate;

import vibe.http.internal.http2.settings;
import vibe.http.internal.http2.hpack.hpack;
import vibe.http.internal.http2.hpack.tables;
import vibe.http.internal.http2.frame;

import vibe.http.common;
import vibe.http.status;
import vibe.http.server;
import vibe.internal.allocator;
import vibe.internal.array;
import vibe.internal.utilallocator: RegionListAllocator;

import std.range;
import std.string;
import std.conv;
import std.traits;
import std.typecons;
import std.algorithm.iteration;
import std.algorithm.mutation;

/**
  * Translation between HTTP/1.1 and HTTP/2 headers, as documented in:
  * RFC 7540 (HTTP/2) section 8
*/

enum StartLine { REQUEST, RESPONSE };

private alias H2F = HTTP2HeaderTableField;

/// accepts a HTTP/1.1 header list, converts it to an HTTP/2 header frame and encodes it
ubyte[] buildHeaderFrame(alias type)(string[] h1header, HTTP2ServerContext context, ref IndexingTable table, scope IAllocator alloc) @safe
{
	// frame header + frame payload
	FixedAppender!(ubyte[], 9) hbuf;
	auto pbuf = AllocAppender!(ubyte[])(alloc);
	auto res = AllocAppender!(ubyte[])(alloc);

	// split the start line of each req / res into pseudo-headers
	convertStartMessage(h1header[0], pbuf, table, type, context.isTLS);
	h1header.popFront();

	// convert and encode the range of headers from HTTP1 to HTTP2
	h1header
		.map!(s => s.strip('\n').replace("Host", ":authority").toLower)
		.filter!(s => !s.empty)
		.each!(s => s.split(": ").H2F.encodeHPACK(pbuf, table));

	// TODO padding
	hbuf.createHTTP2FrameHeader(cast(uint)pbuf.data.length, HTTP2FrameType.SETTINGS, 0x4, 0);
	res.put(hbuf.data);
	res.put(pbuf.data);
	return res.data;
}
/// DITTO
ubyte[] buildHeaderFrame(alias type)(string h1header, HTTP2ServerContext context, ref IndexingTable table, scope IAllocator alloc) @safe
{
	return buildHeaderFrame!type(h1header.split('\r'), context, table, alloc);
}

/// generates an HTTP/2 pseudo-header representation to encode a HTTP/1.1 start message line
private void convertStartMessage(T)(string src, ref T dst, ref IndexingTable table, StartLine type, bool isTLS = true) @safe
{
	void toPseudo(string buf) @safe
	{
		// exclude protocol version (not needed in HTTP/2)
		if(buf != "HTTP/1.1" && buf != "HTTP/2")
		{
			if(type == StartLine.REQUEST) { // request
				//	request-line = method SP request-target SP HTTP-version CRLF
					try {
						auto method = httpMethodFromString(buf);
						H2F(":method", method).encodeHPACK(dst, table);
					} catch(Exception e) {
						H2F(":scheme", (isTLS ? "https" : "http")).encodeHPACK(dst, table);
						H2F(":path", buf).encodeHPACK(dst, table);
					}
			} else if(type == StartLine.RESPONSE) { // response (status-line)
				// status-line = HTTP-version SP status-code SP reason-phrase CRLF
				static foreach(st; __traits(allMembers, HTTPStatus)) {
					if(buf.isNumeric && __traits(getMember, HTTPStatus, st) == buf.to!int) {
						mixin("H2F(\":status\",HTTPStatus."~st~").encodeHPACK(dst, table); return;");
					}
				}
			}
		}
	}

	// consider each chunk of the start message line
	src.splitter(' ').each!(s => toPseudo(s));
}

unittest {
	import std.experimental.allocator;
	import std.experimental.allocator.mallocator;
	HTTP2Settings settings;
	HTTPServerContext ctx;
	auto context = HTTP2ServerContext(ctx, settings);
	context.setNoTLS();
	auto table = IndexingTable(settings.headerTableSize);
	scope alloc = new RegionListAllocator!(shared(Mallocator), false)(1024, Mallocator.instance);

	string header = "GET / HTTP/2\r\nHost: www.example.com\r\n";
	ubyte[] expected = [0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1 , 0xe3, 0xc2 , 0xe5, 0xf2 , 0x3a, 0x6b , 0xa0, 0xab , 0x90, 0xf4 , 0xff];
	// [9..$] excludes the HTTP/2 Frame header
	auto res = buildHeaderFrame!(StartLine.REQUEST)(header, context, table, alloc)[9..$];
	assert(res == expected);

	string resHeader = "HTTP/2 200 OK";
	expected = [0x88];
	res = buildHeaderFrame!(StartLine.RESPONSE)(resHeader, context, table, alloc)[9..$];

	assert(res == expected);
}
