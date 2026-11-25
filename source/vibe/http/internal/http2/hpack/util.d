module vibe.http.internal.http2.hpack.util;

import std.range;

// decode ubyte as integer representation according to prefix
size_t toInteger(ubyte bbuf, uint prefix) @safe @nogc
{
	assert(prefix < 8, "Prefix must be at most an octet long");

	bbuf = bbuf & ((1 << (8 - prefix)) - 1);

	return bbuf;
}

/** Encodes `value` as an HPACK integer with a `prefix` bit wide prefix, appending
	the resulting octets to `dst`.

The lower `prefix` bits of `head` hold the integer, the remaining bits being kept
as given (they usually contain the flags of the field representation). Values
which don't fit into the prefix are continued in 7 bit chunks, as described in
RFC 7541, section 5.1.
*/
void writePrefixedInteger(O)(ubyte head, size_t value, uint prefix, ref O dst)
	if (isOutputRange!(O, ubyte))
{
	assert(prefix < 8, "Prefix must be at most an octet long");

	size_t max = (1 << prefix) - 1; // largest value not needing a continuation

	if (value < max) {
		dst.put(cast(ubyte)(head | value));
		return;
	}

	dst.put(cast(ubyte)(head | max));
	value -= max;

	while (value >= 0x80) {
		dst.put(cast(ubyte)((value & 0x7f) | 0x80));
		value >>= 7;
	}
	dst.put(cast(ubyte)(value));
}

unittest { // values fitting into the prefix use a single octet
	import vibe.internal.array : BatchBuffer;

	BatchBuffer!(ubyte, 1) bres;
	bres.putN(1);
	writePrefixedInteger(cast(ubyte)(0x80), 12, 7, bres);
	assert(bres.peekDst == [0x8c]);
}

unittest { // larger values are continued in additional octets
	import std.array : appender;

	auto bres = appender!(ubyte[])();
	writePrefixedInteger(cast(ubyte)(0x80), 127, 7, bres);
	assert(bres.data == [0xff, 0x00]);

	bres.clear();
	writePrefixedInteger(cast(ubyte)(0x80), 200, 7, bres);
	assert(bres.data == [0xff, 0x49]);
}
