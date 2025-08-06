module vibe.http.internal.http2.hpack.exception;

import std.exception;

T enforceHPACK(T)(T condition, string message = null, string file = __FILE__,
	typeof(__LINE__) line = __LINE__) @safe
{
	return enforce(condition, new HPACKException(message, file, line));
}

class HPACKException : Exception {
	this(string msg, string file = __FILE__, size_t line = __LINE__) @safe
	{
		super(msg, file, line);
	}
}

class HPACKDecoderException : HPACKException {
	this(string msg, string file = __FILE__, size_t line = __LINE__)
	{
		super(msg, file, line);
	}
}

class HPACKEncoderException : HPACKException {
	this(string msg, string file = __FILE__, size_t line = __LINE__)
	{
		super(msg, file, line);
	}
}
