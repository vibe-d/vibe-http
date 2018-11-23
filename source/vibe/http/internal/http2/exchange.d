module vibe.http.internal.http2.response;

import vibe.http.internal.http2.http2;
import vibe.http.internal.http2.hpack.hpack;

private static string[4] pseudoHeaders = [":authority", ":scheme", ":method", ":path"];

enum StartLine { REQUEST, RESPONSE };

/// generates a pseudo-header representation to encode a HTTP/1.1 start message line
/// see RFC 7540, section 8
void convertStartMessage(type)(string src, ref HTTP2HeaderTableField[] dst) @safe @nogc
	if(isInputRange!I && (is(ElementType!I : immutable(ubyte)) || is(ElementType!I : immutable(char))))
{
	static if(type == StartLine.REQUEST) { // request
		// TODO
	} else if(type == StartLine.RESPONSE) { // response (status-line)
		// TODO
	}
}

void writeHeaderFrame(Stream)(Stream h2stream, ref ubyte[] h1header, uint maxVal, IAllocator alloc) @safe @nogc
	if(is(Stream == HTTP2ConnectionStream))
{
    //encodeHPACK(I,R)(h1header, ref R dst, ref IndexingTable table, bool huffman = true) @safe

}
