module hpack.util;

import std.range;

// decode ubyte as integer representation according to prefix
size_t toInteger(ubyte bbuf, uint prefix) @safe @nogc
{
	assert(prefix < 8, "Prefix must be at most an octet long");

	bbuf = bbuf & ((1 << (8 - prefix)) - 1);
	assert(bbuf >= 0, "Invalid decoded integer");

	return bbuf;
}
