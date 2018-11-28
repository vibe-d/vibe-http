module vibe.http.internal.http2.settings;

import vibe.http.internal.http2.frame;
import vibe.http.server;
import vibe.core.log;
import vibe.core.net;

import std.range;
import std.base64;
import std.traits;
import std.bitmanip; // read from ubyte (decoding)
import std.typecons;
import std.conv : to;
import std.exception : enforce;
import std.algorithm : canFind; // alpn callback
import std.variant : Algebraic;

/*
 *  6.5.1.  SETTINGS Format
 *
 *   The payload of a SETTINGS frame consists of zero or more parameters,
 *   each consisting of an unsigned 16-bit setting identifier and an
 *   unsigned 32-bit value.
 *
 *   +-------------------------------+
 *   |	   IDentifier (16)		 |
 *   +-------------------------------+-------------------------------+
 *   |						Value (32)							 |
 *   +---------------------------------------------------------------+
 *						Figure 10: Setting Format
 *
 *   6.5.2.  Defined SETTINGS Parameters
 *
 *   The following parameters are defined:
 *
 *   SETTINGS_HEADER_TABLE_SIZE (0x1):  Allows the sender to inform the
 *	 remote endpoint of the maximum size of the header compression
 *	 table used to decode header blocks, in octets.  The encoder can
 *	 select any size equal to or less than this value by using
 *	 signaling specific to the header compression format inside a
 *	 header block (see [COMPRESSION]).  The initial value is 4,096
 *	 octets.
 *
 *   SETTINGS_ENABLE_PUSH (0x2):  This setting can be used to disable
 *	  server push (Section 8.2).  An endpoint MUST NOT send a
 *	  PUSH_PROMISE frame if it receives this parameter set to a value of
 *	  0.  An endpoint that has both set this parameter to 0 and had it
 *	  acknowledged MUST treat the receipt of a PUSH_PROMISE frame as a
 *	  connection error (Section 5.4.1) of type PROTOCOL_ERROR.
 *
 *	  The initial value is 1, which indicates that server push is
 *	  permitted.  Any value other than 0 or 1 MUST be treated as a
 *	  connection error (Section 5.4.1) of type PROTOCOL_ERROR.
 *
 *	SETTINGS_MAX_CONCURRENT_STREAMS (0x3):  Indicates the maximum number
 *	  of concurrent streams that the sender will allow.  This limit is
 *	  directional: it applies to the number of streams that the sender
 *	  permits the receiver to create.  Initially, there is no limit to
 *	  this value.  It is recommended that this value be no smaller than
 *	  100, so as to not unnecessarily limit parallelism.
 *
 *	  A value of 0 for SETTINGS_MAX_CONCURRENT_STREAMS SHOULD NOT be
 *	  treated as special by endpoints.  A zero value does prevent the
 *	  creation of new streams; however, this can also happen for any
 *	  limit that is exhausted with active streams.  Servers SHOULD only
 *	  set a zero value for short durations; if a server does not wish to
 *	  accept requests, closing the connection is more appropriate.
 *
 *	SETTINGS_INITIAL_WINDOW_SIZE (0x4):  Indicates the sender's initial
 *	   window size (in octets) for stream-level flow control.  The
 *	   initial value is 2^16-1 (65,535) octets.
 *
 *	   This setting affects the window size of all streams (see
 *	   Section 6.9.2).
 *
 *	   Values above the maximum flow-control window size of 2^31-1 MUST
 *	   be treated as a connection error (Section 5.4.1) of type
 *	   FLOW_CONTROL_ERROR.
 *
 *	SETTINGS_MAX_FRAME_SIZE (0x5):  Indicates the size of the largest
 *	   frame payload that the sender is willing to receive, in octets.
 *
 *	   The initial value is 2^14 (16,384) octets.  The value advertised
 *	   by an endpoint MUST be between this initial value and the maximum
 *	   allowed frame size (2^24-1 or 16,777,215 octets), inclusive.
 *	   Values outside this range MUST be treated as a connection error
 *	   (Section 5.4.1) of type PROTOCOL_ERROR.
 *
 *	SETTINGS_MAX_HEADER_LIST_SIZE (0x6):  This advisory setting informs a
 *	   peer of the maximum size of header list that the sender is
 *	   prepared to accept, in octets.  The value is based on the
 *	   uncompressed size of header fields, including the length of the
 *	   name and value in octets plus an overhead of 32 octets for each
 *	   header field.
 *
 *	   For any given request, a lower limit than what is advertised MAY
 *	   be enforced.  The initial value of this setting is unlimited.
 *
 *   An endpoint that receives a SETTINGS frame with any unknown or
 *   unsupported identifier MUST ignore that setting.
*/
//version = VibeForceALPN;

alias HTTP2SettingID = ushort;
alias HTTP2SettingValue = uint;

// useful for bound checking
const HTTP2SettingID minID = 0x1;
const HTTP2SettingID maxID = 0x6;

enum  HTTP2SettingsParameter {
	headerTableSize				 = 0x1,
	enablePush					  = 0x2,
	maxConcurrentStreams			= 0x3,
	initialWindowSize			   = 0x4,
	maxFrameSize					= 0x5,
	maxHeaderListSize			   = 0x6
}

// UDAs
struct HTTP2Setting {
	HTTP2SettingID id;
	string name;
}

// UDAs
HTTP2Setting http2Setting(HTTP2SettingID id, string name) {
	if (!__ctfe) assert(false, "May only be used as a UDA");
	return HTTP2Setting(id, name);
}

struct HTTP2Settings {

	// no limit specified in the RFC
	@http2Setting(0x1, "SETTINGS_HEADER_TABLE_SIZE")
	HTTP2SettingValue headerTableSize = 4096;

	// TODO {0,1} otherwise CONNECTION_ERROR
	@http2Setting(0x2, "SETTINGS_ENABLE_PUSH")
	HTTP2SettingValue enablePush = 1;

	/* set to the max value (UNLIMITED)
	 * TODO manage connection with value == 0
	 * might be closed as soon as possible
	 */
	@http2Setting(0x3, "SETTINGS_MAX_CONCURRENT_STREAMS")
	HTTP2SettingValue maxConcurrentStreams = HTTP2SettingValue.max;

	// TODO FLOW_CONTROL_ERRROR on values > 2^31-1
	@http2Setting(0x4, "SETTINGS_INITIAL_WINDOW_SIZE")
	HTTP2SettingValue initialWindowSize = 65535;

	// TODO PROTOCOL_ERROR on values > 2^24-1
	@http2Setting(0x5, "SETTINGS_MAX_FRAME_SIZE")
	HTTP2SettingValue maxFrameSize = 16384;

	// set to the max value (UNLIMITED)
	@http2Setting(0x6, "SETTINGS_MAX_HEADER_LIST_SIZE")
	HTTP2SettingValue maxHeaderListSize = HTTP2SettingValue.max;

	/**
	 * Use Decoder to decode a string and set the corresponding settings
	 * The decoder must follow the base64url encoding
	 * `bool` since the handler must ignore the Upgrade request
	 * if the settings cannot be decoded
	 */
	bool decode(alias Decoder)(string encodedSettings) @safe
		if (isInstanceOf!(Base64Impl, Decoder))
	{
		ubyte[] uset;
		try {
			// the Base64URL decoder throws a Base64exception if it fails
			uset = Decoder.decode(encodedSettings);
			enforce!Base64Exception(uset.length % 6 == 0, "Invalid SETTINGS payload length");
		} catch (Base64Exception e) {
			logDiagnostic("Failed to decode SETTINGS payload: " ~ e.msg);
			return false;
		}

		// set values
		while(!uset.empty) m_set(uset.read!HTTP2SettingID, uset.read!HTTP2SettingValue);
		return true;
	}

	/*
	 * Set parameter 'id' to 'value'
	 * private overload for decoded parameters assignment
	 */
	void set(HTTP2SettingID id)(HTTP2SettingValue value) @safe
		if(id <= maxID && id >= minID)
	{
		m_set(id,value);
	}

	private void m_set(HTTP2SettingID id, HTTP2SettingValue value) @safe
	{
		// must use labeled break w. static foreach
		assign: switch(id) {
			default: logWarn("Unsupported SETTINGS code:" ~ to!string(id)); return;
			static foreach(c; __traits(allMembers, HTTP2SettingsParameter)) {
				case __traits(getMember, HTTP2SettingsParameter, c):
					__traits(getMember, this, c) = value;
					break assign;
			}
		}
	}

}

void serializeSettings(R)(ref R dst, HTTP2Settings settings) @safe @nogc
{
	static foreach(s; __traits(allMembers, HTTP2Settings)) {
		static if(is(typeof(__traits(getMember, HTTP2Settings, s)) == HTTP2SettingValue)) {
			mixin("dst.putBytes!2((getUDAs!(settings."~s~",HTTP2Setting)[0]).id);");
			mixin("dst.putBytes!4(settings."~s~");");
		}
	}
}

void unpackSettings(R)(ref HTTP2Settings settings, R src) @safe @nogc
{
	while(!src.empty) {
		auto id = src.takeExactly(2).fromBytes(2);
		src.popFrontN(2);
		static foreach(s; __traits(allMembers, HTTP2Settings)) {
			static if(is(typeof(__traits(getMember, HTTP2Settings, s)) == HTTP2SettingValue)) {
				mixin("if(id == ((getUDAs!(settings."~s~",HTTP2Setting)[0]).id)) {
							settings."~s~" = src.takeExactly(4).fromBytes(4);
							src.popFrontN(4);
						}");

			}
		}
	}
}

unittest {

	HTTP2Settings settings;

	// retrieve a value
	assert(settings.headerTableSize == 4096);

	//set a SETTINGS value using the enum table
	settings.set!(HTTP2SettingsParameter.headerTableSize)(2048);
	assert(settings.headerTableSize == 2048);

	//set a SETTINGS value using the code directly
	settings.set!0x4(1024);
	assert(settings.initialWindowSize == 1024);

	// SHOULD NOT COMPILE
	//settings.set!0x7(1);

	// get a HTTP2Setting struct containing the code and the parameter name
	import std.traits : getUDAs;
	assert(getUDAs!(settings.headerTableSize, HTTP2Setting)[0] == HTTP2Setting(0x1,
				"SETTINGS_HEADER_TABLE_SIZE"));

	// test decoding from base64url
	// h2settings contains:
	// 0x2 -> 0
	// 0x3 -> 100
	// 0x4 -> 1073741824
	string h2settings = "AAMAAABkAARAAAAAAAIAAAAA";
	assert(settings.decode!Base64URL(h2settings));

	assert(settings.enablePush == 0);
	assert(settings.maxConcurrentStreams == 100);
	assert(settings.initialWindowSize == 1073741824);

	// should throw a Base64Exception error (caught) and a logWarn
	assert(!settings.decode!Base64URL("a|b+*-c"));
}

struct HTTP2ServerContext
{
	private {
		HTTPServerContext m_context;
		Nullable!HTTP2Settings m_settings;
		uint m_sid = 0;
		bool m_isTLS = true;
	}

	// used to mantain the first request in case of `h2c` protocol switching
	Nullable!(ubyte[]) resHeader;
	Nullable!(ubyte[]) resBody;

	this(HTTPServerContext ctx, HTTP2Settings settings) @safe
	{
		m_context = ctx;
		m_settings = settings;
	}

	this(HTTPServerContext ctx) @safe
	{
		m_context = ctx;
	}

	alias m_context this;

	@property HTTPServerContext h1context() @safe @nogc { return m_context; }

	@property uint next_sid() @safe @nogc { assert(m_sid % 2 == 0); m_sid += 2; return m_sid; }

	@property bool isTLS() @safe @nogc { return m_isTLS; }

	@property void setNoTLS() @safe @nogc { m_isTLS = false; }

	@property ref HTTP2Settings settings() @safe @nogc
	{
		assert(!m_settings.isNull);
		return m_settings;
	}

	@property void settings(ref HTTP2Settings settings) @safe @nogc
	{
		assert(m_settings.isNull);
		m_settings = settings;
	}
}

