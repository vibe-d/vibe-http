module vibe.http.internal.utils;

import core.time : nsecs, seconds;
import std.datetime : SysTime;
import vibe.container.internal.appender : FixedAppender;
import vibe.inet.message : writeRFC822DateTimeString;


string formatRFC822DateAlloc(SysTime time)
@safe {
	static LAST = CacheTime(SysTime.min());

	if (time > LAST.nextUpdate) {
		auto app = new FixedAppender!(string, 32);
		writeRFC822DateTimeString(app, time);
		LAST.update(time);
		LAST.cachedDate = () @trusted { return app.data; } ();
		return () @trusted { return app.data; } ();
	} else
		return LAST.cachedDate;
}

private struct CacheTime
{
	string cachedDate;
	SysTime nextUpdate;

	this(SysTime nextUpdate) @safe @nogc pure nothrow
	{
		this.nextUpdate = nextUpdate;
	}

	void update(SysTime time) @safe
	{
		this.nextUpdate = time + 1.seconds;
		this.nextUpdate.fracSecs = nsecs(0);
	}
}
