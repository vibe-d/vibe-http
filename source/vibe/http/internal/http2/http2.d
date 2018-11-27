module vibe.http.internal.http2.http2;

import vibe.http.internal.http2.frame;
import vibe.http.internal.http2.settings;
import vibe.http.internal.http2.hpack.tables;
import vibe.http.server;

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
import std.variant : Algebraic;

/*
   3.2.  Starting HTTP/2 for "http" URIs

   A client that makes a request for an "http" URI without prior
   knowledge about support for HTTP/2 on the next hop uses the HTTP
   Upgrade mechanism (Section 6.7 of [RFC7230]).  The client does so by
   making an HTTP/1.1 request that includes an Upgrade header field with
   the "h2c" token.  Such an HTTP/1.1 request MUST include exactly one
   HTTP2-Settings (Section 3.2.1) header field.

   For example:

	 GET / HTTP/1.1
	 Host: server.example.com
	 Connection: Upgrade, HTTP2-Settings
	 Upgrade: h2c
	 HTTP2-Settings: <base64url encoding of HTTP/2 SETTINGS payload>

   Requests that contain a payload body MUST be sent in their entirety
   before the client can send HTTP/2 frames.  This means that a large
   request can block the use of the connection until it is completely
   sent.

   If concurrency of an initial request with subsequent requests is
   important, an OPTIONS request can be used to perform the upgrade to
   HTTP/2, at the cost of an additional round trip.


   A server that does not support HTTP/2 can respond to the request as
   though the Upgrade header field were absent:

	 HTTP/1.1 200 OK
	 Content-Length: 243
	 Content-Type: text/html

	 ...

   A server MUST ignore an "h2" token in an Upgrade header field.
   Presence of a token with "h2" implies HTTP/2 over TLS, which is
   instead negotiated as described in Section 3.3.

   A server that supports HTTP/2 accepts the upgrade with a 101
   (Switching Protocols) response.  After the empty line that terminates
   the 101 response, the server can begin sending HTTP/2 frames.  These
   frames MUST include a response to the request that initiated the
   upgrade.

   For example:

	 HTTP/1.1 101 Switching Protocols
	 Connection: Upgrade
	 Upgrade: h2c

	 [ HTTP/2 connection ...

   The first HTTP/2 frame sent by the server MUST be a server connection
   preface (Section 3.5) consisting of a SETTINGS frame (Section 6.5).
   Upon receiving the 101 response, the client MUST send a connection
   preface (Section 3.5), which includes a SETTINGS frame.

   The HTTP/1.1 request that is sent prior to upgrade is assigned a
   stream identifier of 1 (see Section 5.1.1) with default priority
   values (Section 5.3.5).  Stream 1 is implicitly "half-closed" from
   the client toward the server (see Section 5.1), since the request is
   completed as an HTTP/1.1 request.  After commencing the HTTP/2
   connection, stream 1 is used for the response.

3.2.1.  HTTP2-Settings Header Field

   A request that upgrades from HTTP/1.1 to HTTP/2 MUST include exactly
   one "HTTP2-Settings" header field.  The HTTP2-Settings header field
   is a connection-specific header field that includes parameters that
   govern the HTTP/2 connection, provided in anticipation of the server
   accepting the request to upgrade.

	 HTTP2-Settings	= token68

   A server MUST NOT upgrade the connection to HTTP/2 if this header
   field is not present or if more than one is present.  A server MUST
   NOT send this header field.

   The content of the HTTP2-Settings header field is the payload of a
   SETTINGS frame (Section 6.5), encoded as a base64url string (that is,
   the URL- and filename-safe Base64 encoding described in Section 5 of
   [RFC4648], with any trailing '=' characters omitted).  The ABNF
   [RFC5234] production for "token68" is defined in Section 2.1 of
   [RFC7235].

   Since the upgrade is only intended to apply to the immediate
   connection, a client sending the HTTP2-Settings header field MUST
   also send "HTTP2-Settings" as a connection option in the Connection
   header field to prevent it from being forwarded (see Section 6.1 of
   [RFC7230]).

   A server decodes and interprets these values as it would any other
   SETTINGS frame.  Explicit acknowledgement of these settings
   (Section 6.5.3) is not necessary, since a 101 response serves as
   implicit acknowledgement.  Providing these values in the upgrade
   request gives a client an opportunity to provide parameters prior to
   receiving any frames from the server.

*/


/*
 * Check if SETTINGS payload is valid by trying to decode it
 * if !valid, close connection and refuse to upgrade (RFC) - TODO discuss
 * if valid, send SWITCHING_PROTOCOL response and start an HTTP/2 connection handler
 */
bool startHTTP2Connection(ConnectionStream)(ConnectionStream connection, string h2settings,
		HTTP2ServerContext context, HTTPServerResponse switchRes) @safe
	if (isConnectionStream!ConnectionStream)
{
	// init settings
	HTTP2Settings settings;
	logInfo("Starting HTTP/2 connection");

	// try decoding settings
	if (settings.decode!Base64URL(h2settings)) {
		// send response
		context.settings = settings;
		switchRes.switchToHTTP2(&handleHTTP2Connection!ConnectionStream, context);
		return true;
	} else {
		// reply with a 400 (bad request) header
		switchRes.sendBadRequest();
		connection.close;
		return false;
	}
}

unittest {
	import vibe.core.core : runApplication;
	// empty handler, just to test if protocol switching works
	void handleReq(HTTPServerRequest req, HTTPServerResponse res)
	@safe {
		if (req.path == "/")
		res.writeBody("Hello, World! This response is sent through HTTP/2");
	}

	auto settings = HTTPServerSettings();
	settings.port = 8090;
	settings.bindAddresses = ["localhost"];

	listenHTTP!handleReq(settings);
	//runApplication();
}

unittest {
	//import vibe.core.core : runApplication;

	void handleRequest (HTTPServerRequest req, HTTPServerResponse res)
	@safe {
		if (req.path == "/")
		res.writeBody("Hello, World! This response is sent through HTTP/2");
	}


	HTTPServerSettings settings;
	settings.port = 8091;
	settings.bindAddresses = ["127.0.0.1"];
	settings.tlsContext = createTLSContext(TLSContextKind.server);
	settings.tlsContext.useCertificateChainFile("tests/server.crt");
	settings.tlsContext.usePrivateKeyFile("tests/server.key");

	// set alpn callback to support HTTP/2
	// should accept the 'h2' protocol request
	settings.tlsContext.alpnCallback = http2Callback;

	// dummy, just for testing
	listenHTTP!handleRequest(settings);
	runApplication();
}

/**
  * an ALPN callback which can be used to detect the "h2" protocol
  * must be set before initializing the server with 'listenHTTP'
  * if the protocol is not set, it replies with HTTP/1.1
  */
TLSALPNCallback http2Callback = (string[] choices) {
	logInfo("http2Callback");
	if (choices.canFind("h2")) return "h2";
	else return "http/1.1";
};

private alias TLSStreamType = ReturnType!(createTLSStreamFL!(InterfaceProxy!Stream));

/** server & client should send a connection preface
  * server should receive a connection preface from the client
  * server connection preface consists of a SETTINGS Frame
  */
void handleHTTP2Connection(ConnectionStream)(ConnectionStream stream, TCPConnection connection, HTTP2ServerContext context) @safe
	if (isConnectionStream!ConnectionStream || is(ConnectionStream : TLSStreamType))
{
	logInfo("HTTP/2 Connection Handler");

	// read the connection preface
	ubyte[24] h2connPreface;
	stream.read(h2connPreface);

	assert(h2connPreface == "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "Invalid HTTP/2 h2stream preface");
	logInfo("Received client h2stream preface");

	// send SETTINGS Frame
	ubyte[45] settingBuf;
	FixedAppender!(ubyte[], HTTP2HeaderLength+36) settingDst;
	settingDst.createHTTP2FrameHeader(36, HTTP2FrameType.SETTINGS, 0x0, 0);
	settingDst.serializeSettings(context.settings);
	stream.write(settingDst.data);

	() @trusted {
		IndexingTable table = IndexingTable(context.settings.headerTableSize);
		handleHTTP2FrameChain(connection, context);
	} ();
}

private void handleHTTP2FrameChain(ConnectionStream)(ConnectionStream connection, HTTP2ServerContext context) @safe
	if (isConnectionStream!ConnectionStream || is(ConnectionStream : TLSStream))
{
	logInfo("HTTP/2 Frame Chain Handler");

	static struct CB {
		ConnectionStream connection;
		HTTP2ServerContext context;

		void opCall(bool st)
		{
			if (!st) connection.close;
			else runTask(&handleHTTP2FrameChain, connection, context);
		}
	}

	while(true) {
		CB cb = {connection, context};
		auto st = connection.waitForDataAsync(cb);

		final switch(st) {
			case WaitForDataAsyncStatus.waiting: return;
			case WaitForDataAsyncStatus.noMoreData: connection.close; return;
			case WaitForDataAsyncStatus.dataAvailable: handleHTTP2Frame(connection, context); break;
		}
	}
}

private void handleHTTP2Frame(ConnectionStream)(ConnectionStream connection, HTTP2ServerContext context) @safe
	if (isConnectionStream!ConnectionStream || is(ConnectionStream : TLSStream))
{
	logInfo("HTTP/2 Frame Handler");
	auto h2stream = HTTP2ConnectionStream!ConnectionStream(connection, context.next_sid);

	() @trusted {

		import vibe.internal.utilallocator: RegionListAllocator;
		version (VibeManualMemoryManagement)
			scope alloc = new RegionListAllocator!(shared(Mallocator), false)(1024, Mallocator.instance);
		else
			scope alloc = new RegionListAllocator!(shared(GCAllocator), true)(1024, GCAllocator.instance);
		handleFrameAlloc(h2stream, context, alloc);

	} ();

}

private void handleFrameAlloc(ConnectionStream)(ConnectionStream stream, HTTP2ServerContext context, IAllocator alloc) @safe
{
	logInfo("HTTP/2 Frame Handler (Alloc)");

	// payload buffer
	auto rawBuf = AllocAppender!(ubyte[])(alloc);
	auto payload = AllocAppender!(ubyte[])(alloc);

	// Frame properties
	bool endStream = false;
	bool needsCont = false;
	bool isAck = false;
	HTTP2FrameStreamDependency sdep;

	// read header
	stream.readHeader(rawBuf);
	auto len = rawBuf.data[0..3].fromBytes(3);

	// adjust buffer sizes
	rawBuf.reserve(len);
	payload.reserve(len);

	// read payload
	stream.readPayload(rawBuf, len);

	// parse frame
	auto header = payload.unpackHTTP2Frame(rawBuf.data, endStream, needsCont, isAck, sdep);

	logInfo("Received: "~to!string(header.type)~" on streamID "~to!string(header.streamId));

	// build reply according to frame type
	final switch(header.type) {
		case HTTP2FrameType.DATA:
			if(endStream) {
				// close stream `stream.streamId`
			}
			break;

		case HTTP2FrameType.HEADERS:
			if(sdep.isSet) {
				// update stream dependency with data in `sdep`
			}
			if(needsCont) {
				// wait for the next header frame until end_headers flag is set
				// END_STREAM flag does not count in this case
			}
			if(endStream) {
				// close stream `stream.streamId`
			}
			break;

		case HTTP2FrameType.PRIORITY:
			// update stream dependency with data in `sdep`
			break;

		case HTTP2FrameType.RST_STREAM:
			// reset stream in `closed` state
			// payload contains error code
			break;

		case HTTP2FrameType.SETTINGS:
			if(!isAck) {
				// parse settings payload
				context.settings.unpackSettings(payload.data);
				// acknowledge settings with SETTINGS ACK Frame
				FixedAppender!(ubyte[], 9) ackReply;
				ackReply.createHTTP2FrameHeader(0, header.type, 0x1, header.streamId);
				stream.write(ackReply.data);
				logInfo("Sent SETTINGS ACK");
			}
			break;

		case HTTP2FrameType.PUSH_PROMISE:
			// reserve a streamId to be created (in payload)
			// if not possible, CONNECTION_ERROR (invalid stream id)
			//
			// process header sent (in payload)
			if(needsCont) {
				// wait for the next header frame until end_headers flag is set
			}
			break;

		case HTTP2FrameType.PING:
			if(!isAck) {
				// acknowledge ping with PING ACK Frame
				rawBuf.reserve(HTTP2HeaderLength + len);
				rawBuf.createHTTP2FrameHeader(len, header.type, 0x1, header.streamId);
				rawBuf.buildHTTP2Frame(payload.data);

				stream.write(rawBuf.data);
			}
			break;

		case HTTP2FrameType.GOAWAY: // GOAWAY is used to close connection (in handler)
			// set LAST_STREAM_ID to the received value
			// report error code & additional debug info
			// respond with GOAWAY
			//rawBuf.reserve(HTTP2HeaderLength + len);
			//rawBuf.createHTTP2FrameHeader(len, header.type, 0x0, 0);
			//rawBuf.buildHTTP2Frame(payload.data);
			//stream.write(rawBuf.data);
			// terminate connection
			//stream.close();
			break;

		case HTTP2FrameType.WINDOW_UPDATE:
			// TODO per-stream and connection-based flow control
			// window size is a uint (31) in payload
			// update window size for DATA Frames flow control
			break;

		case HTTP2FrameType.CONTINUATION:
			// process header block fragment in payload
			if(needsCont) {
				// wait for the next header frame until end_headers flag is set
			}
			break;
	}
}

enum HTTP2StreamState {
	IDLE,
	RESERVED_LOCAL,
	RESERVED_REMOTE,
	OPEN,
	HALF_CLOSED_LOCAL,
	HALF_CLOSED_REMOTE,
	CLOSED
}

// based on TCPConnection
// added methods for compliance with the Stream class
struct HTTP2ConnectionStream(CS)
{
	static assert(isConnectionStream!CS || is(CS : TLSStream) || isOutputStream!Stream);

	private {
		enum Parse { HEADER, PAYLOAD };
		CS m_conn;
		const uint m_streamId; // streams initiated by the server must be even-numbered
		Parse toParse = Parse.HEADER;

		// TODO manage the underlying HTTP/1.1 request
		HTTPServerRequest m_req;
		HTTPServerResponse m_res;
	}

	alias m_conn this;
	HTTP2StreamState state;

	this(CS)(ref CS conn, uint sid) @safe
	{
		m_conn = conn;
		m_streamId = sid;
		state = HTTP2StreamState.IDLE;
	}

	this(CS)(ref CS conn) @safe
	{
		this(conn, 0);
	}

	@property uint streamId() @safe @nogc { return m_streamId; }

	void readHeader(R)(ref R dst) @safe
	{
		assert(toParse == Parse.HEADER);
		toParse = Parse.PAYLOAD;

		ubyte[9] buf;
		m_conn.read(buf);
		dst.put(buf);
	}

	void readPayload(R)(ref R dst, int len) @safe
	{
		assert(toParse == Parse.PAYLOAD);
		toParse = Parse.HEADER;

		ubyte[8] buf = void;
		while(len > 0) {
			auto end = (len < buf.length) ? len : buf.length;
			len -= m_conn.read(buf[0..end], IOMode.all);
			dst.put(buf[0..end]);
		}
	}
}

unittest {
	TCPConnection c;
	auto h2 = HTTP2ConnectionStream!TCPConnection(c, 1);

	assert(h2.empty);
	assert(h2.streamId == 1);
}
