module vibe.http.headers;

import taggedalgebraic;
import std.datetime.systime : SysTime;
import std.typecons : Tuple;

struct HTTPHeaderValueTypes {
	Tuple!(const(char)[], const(char)[]) generic;
	SysTime date;
	long contentLength;
}

alias HTTPHeaderValue = TaggedAlgebraic!HTTPHeaderValueTypes;
