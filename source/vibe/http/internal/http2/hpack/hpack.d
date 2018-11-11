//module vibe.http.internal.hpack.hpack;
module hpack.hpack;

import hpack.encoder;
import hpack.decoder;
import hpack.tables;


import std.range;
import std.typecons;
import std.array; // appender
import std.algorithm.iteration;


void encodeHPACK(I,R)(I src, ref R dst, ref IndexingTable table, bool huffman = true) @safe
	if(is(I == HTTP2HeaderTableField) || is(ElementType!I : HTTP2HeaderTableField))
{
	static if(is(I == HTTP2HeaderTableField)) {
		src.encode(dst, table, huffman);
	} else if(is(ElementType!I : HTTP2HeaderTableField)){
		src.each!(h => h.encode(dst, table, huffman));
	}
}

void decodeHPACK(I,R,T)(I src, ref R dst, ref IndexingTable table, ref T alloc) @safe
	if(isInputRange!I && (is(ElementType!I : immutable(ubyte)) || is(ElementType!I : immutable(char))))
{
	while(!src.empty) src.decode(dst, table, alloc);
}

/// ENCODER
unittest {
	//// Following examples can be found in Appendix C of the HPACK RFC
	import vibe.http.status;
	import vibe.http.common;
	import vibe.internal.utilallocator: RegionListAllocator;
	import std.experimental.allocator;
	import std.experimental.allocator.gc_allocator;

	IndexingTable table = IndexingTable(4096);
	scope alloc = new RegionListAllocator!(shared(GCAllocator), false)(1024, GCAllocator.instance);

	/** 1. Literal header field w. indexing (raw)
	  * custom-key: custom-header
	  */
	HTTP2HeaderTableField h1 = HTTP2HeaderTableField("custom-key", "custom-header");
	auto e1 = appender!(ubyte[]);
	auto dec1 = appender!(HTTP2HeaderTableField[]);

	h1.encodeHPACK(e1, table, false);
	decodeHPACK(cast(immutable(ubyte)[])e1.data, dec1, table, alloc);
	assert(dec1.data.front == h1);

	/** 1bis. Literal header field w. indexing (huffman encoded)
	  * :authority: www.example.com
	  */
	table.insert(HTTP2HeaderTableField(":authority", "www.example.com"));
	HTTP2HeaderTableField h1b = HTTP2HeaderTableField(":authority", "www.example.com");
	h1b.neverIndex = false;
	h1b.index = true;
	auto e1b = appender!(ubyte[]);
	auto dec1b = appender!(HTTP2HeaderTableField[]);

	h1b.encodeHPACK(e1b, table, true);
	decodeHPACK(cast(immutable(ubyte)[])e1b.data, dec1b, table, alloc);
	assert(dec1b.data.front == h1b);

	/** 2. Literal header field without indexing (raw)
	  * :path: /sample/path
	  */
	auto h2 = HTTP2HeaderTableField(":path", "/sample/path");
	h2.neverIndex = false;
	h2.index = false;
	// initialize with huffman=false (can be modified by e2.huffman)
	auto e2 = appender!(ubyte[]);
	auto dec2 = appender!(HTTP2HeaderTableField[]);

	h2.encodeHPACK(e2, table, false);
	decodeHPACK(cast(immutable(ubyte)[])e2.data, dec2, table, alloc);
	assert(dec2.data.front == h2);

	/** 3. Literal header field never indexed (raw)
	  * password: secret
	  */
	HTTP2HeaderTableField h3 = HTTP2HeaderTableField("password", "secret");
	h3.neverIndex = true;
	h3.index = false;
	auto e3 = appender!(ubyte[]);
	auto dec3 = appender!(HTTP2HeaderTableField[]);

	h3.encodeHPACK(e3, table, false);
	decodeHPACK(cast(immutable(ubyte)[])e3.data, dec3, table, alloc);
	assert(dec3.data.front == h3);

	/** 4. Indexed header field (integer)
	  * :method: GET
	  */
	HTTP2HeaderTableField h4 = HTTP2HeaderTableField(":method", HTTPMethod.GET);
	auto e4 = appender!(ubyte[]);
	auto dec4 = appender!(HTTP2HeaderTableField[]);

	h4.encodeHPACK(e4, table);
	decodeHPACK(cast(immutable(ubyte)[])e4.data, dec4, table, alloc);
	assert(dec4.data.front == h4);

	/** 5. Full request without huffman encoding
	  * :method: GET
      * :scheme: http
      * :path: /
      * :authority: www.example.com
      * cache-control: no-cache
	  */
	HTTP2HeaderTableField[] block = [
		HTTP2HeaderTableField(":method", HTTPMethod.GET),
		HTTP2HeaderTableField(":scheme", "http"),
		HTTP2HeaderTableField(":path", "/"),
		HTTP2HeaderTableField(":authority", "www.example.com"),
		HTTP2HeaderTableField("cache-control", "no-cache")
	];

	ubyte[14] expected = [0x82, 0x86, 0x84, 0xbe, 0x58, 0x08, 0x6e, 0x6f, 0x2d, 0x63, 0x61, 0x63, 0x68, 0x65];
	auto bres = appender!(ubyte[]);
	block.encodeHPACK(bres, table, false);
	assert(bres.data == expected);

	/** 5. Full request with huffman encoding
	  * :method: GET
      * :scheme: http
      * :path: /
      * :authority: www.example.com
      * cache-control: no-cache
	  */
	ubyte[12] eexpected = [0x82, 0x86, 0x84, 0xbe, 0x58, 0x86, 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf];
	auto bbres = appender!(ubyte[]);
	block.encodeHPACK(bbres, table, true);
	assert(bbres.data == eexpected);
}

/// DECODER
unittest {
	//// Following examples can be found in Appendix C of the HPACK RFC

	import vibe.internal.utilallocator: RegionListAllocator;
	import std.experimental.allocator;
	import std.experimental.allocator.gc_allocator;

	IndexingTable table = IndexingTable(4096);
	scope alloc = new RegionListAllocator!(shared(GCAllocator), false)(1024, GCAllocator.instance);

	/** 1. Literal header field w. indexing (raw)
	  * custom-key: custom-header
	  */
	immutable(ubyte)[] block = [0x40, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65, 0x79,
		0x0d, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72];

	//auto decoder = HeaderDecoder!(ubyte[])(block, table);
	auto dec1 = appender!(HTTP2HeaderTableField[]);
	block.decodeHPACK(dec1, table, alloc);
	assert(dec1.data.front.name == "custom-key" && dec1.data.front.value == "custom-header");
	// check entries to be inserted in the indexing table (dynamic)
	assert(dec1.data.front.index);

	/** 1bis. Literal header field w. indexing (huffman encoded)
	  * :authority: www.example.com
	  */
	block = [0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff];
	auto dec1b = appender!(HTTP2HeaderTableField[]);
	block.decodeHPACK(dec1b, table, alloc);
	assert(dec1b.data.front.name == ":authority" && dec1b.data.front.value == "www.example.com");
	assert(dec1b.data.front.index);

	/** 2. Literal header field without indexing (raw)
	  * :path: /sample/path
	  */
	block = [0x04, 0x0c, 0x2f, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2f, 0x70, 0x61, 0x74, 0x68];
	auto dec2 = appender!(HTTP2HeaderTableField[]);
	block.decodeHPACK(dec2, table, alloc);
	assert(dec2.data.front.name == ":path" && dec2.data.front.value == "/sample/path");


	/** 3. Literal header field never indexed (raw)
	  * password: secret
	  */
	block = [0x10, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x06, 0x73, 0x65,
		  0x63, 0x72, 0x65, 0x74];
	auto dec3 = appender!(HTTP2HeaderTableField[]);
	block.decodeHPACK(dec3, table, alloc);
	assert(dec3.data.front.name == "password" && dec3.data.front.value == "secret");
	assert(dec3.data.front.neverIndex);


	/** 4. Indexed header field (integer)
	  * :method: GET
	  */
	import vibe.http.common;
	block = [0x82];
	auto dec4 = appender!(HTTP2HeaderTableField[]);
	block.decodeHPACK(dec4, table, alloc);
	assert(dec4.data.front.name == ":method" && dec4.data.front.value == HTTPMethod.GET);

	/** 5. Full request without huffman encoding
	  * :method: GET
      * :scheme: http
      * :path: /
      * :authority: www.example.com
      * cache-control: no-cache
	  */
	block = [0x82, 0x86, 0x84, 0xbe, 0x58, 0x08, 0x6e, 0x6f, 0x2d, 0x63, 0x61, 0x63, 0x68, 0x65];
	table.insert(HTTP2HeaderTableField(":authority", "www.example.com"));
	auto decR1 = appender!(HTTP2HeaderTableField[]);
	block.decodeHPACK(decR1, table, alloc);
	HTTP2HeaderTableField[] expected = [
		HTTP2HeaderTableField(":method", HTTPMethod.GET),
		HTTP2HeaderTableField(":scheme", "http"),
		HTTP2HeaderTableField(":path", "/"),
		HTTP2HeaderTableField(":authority", "www.example.com"),
		HTTP2HeaderTableField("cache-control", "no-cache")];

	foreach(i,h; decR1.data.enumerate(0)) {
		assert(h == expected[i]);
	}

	/** 5. Full request with huffman encoding
	  * :method: GET
	  * :scheme: http
	  * :path: /
	  * :authority: www.example.com
	  * cache-control: no-cache
	  */
	block = [0x82, 0x86, 0x84, 0xbe, 0x58, 0x86, 0xa8, 0xeb, 0x10, 0x64, 0x9c,0xbf];
	auto decR2 = appender!(HTTP2HeaderTableField[]);
	block.decodeHPACK(decR2, table, alloc);

	foreach(i,h; decR2.data.enumerate(0)) {
		assert(h == expected[i]);
	}
}


/// Mallocator
unittest {
	import vibe.internal.utilallocator: RegionListAllocator;
	import std.experimental.allocator;
	import std.experimental.allocator.mallocator;
	import std.experimental.allocator.gc_allocator;
	auto table = IndexingTable(4096);
	/** 1bis. Literal header field w. indexing (huffman encoded)
	  * :authority: www.example.com
	  */
	immutable(ubyte)[] block = [0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff];
	scope alloc = new RegionListAllocator!(shared(Mallocator), false)(1024, Mallocator.instance);

	auto dec1b = appender!(HTTP2HeaderTableField[]);
	block.decodeHPACK(dec1b, table, alloc);
	assert(dec1b.data.front.name == ":authority" && dec1b.data.front.value == "www.example.com");
	assert(dec1b.data.front.index);
}
