module vibe.http.internal.http2.http2;

import vibe.http.internal.http2.error;
import vibe.http.internal.http2.multiplexing;
import vibe.http.internal.http2.frame;
import vibe.http.internal.http2.settings;
import vibe.http.internal.http2.exchange;
import vibe.http.internal.http2.hpack.tables;
import vibe.http.internal.http2.hpack.hpack;
import vibe.http.internal.http2.hpack.exception;
import vibe.http.server;

import vibe.container.internal.utilallocator;
import vibe.core.log;
import vibe.core.net;
import vibe.core.core;
import vibe.core.stream;
import vibe.stream.tls;
import vibe.internal.array;
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
import std.algorithm.iteration;
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

/**
  * an ALPN callback which can be used to detect the "h2" protocol
  * must be set before initializing the server with 'listenHTTP'
  * if the protocol is not set, it replies with HTTP/1.1
  */
TLSALPNCallback http2Callback = (string[] choices) {
	if (choices.canFind("h2")) return "h2";
	else return "http/1.1";
};

private alias TLSStreamType = ReturnType!(createTLSStreamFL!(InterfaceProxy!Stream));

/* ==================================================== */
/* 				CONNECTION INITIALIZATION				*/
/* ==================================================== */

/** h2c protocol switching ONLY: Check if SETTINGS payload is valid by trying to decode it
  * if !valid, close connection and refuse to upgrade (RFC)
  * if valid, send SWITCHING_PROTOCOL response and start an HTTP/2 connection handler
  */
bool startHTTP2Connection(ConnectionStream, H)(ConnectionStream connection, string h2settings,
		HTTP2ServerContext context, HTTPServerResponse switchRes, H headers, string st,
		IAllocator alloc, ubyte[] resBody) @safe
	if (isConnectionStream!ConnectionStream)
{
	// init settings
	HTTP2Settings settings;
	logTrace("Starting HTTP/2 connection");

	// try decoding settings
	if (settings.decode!Base64URL(h2settings)) {

		context.settings = settings;

		// initialize IndexingTable (HPACK)
		() @trusted {

			if(!context.hasTable) context.table = FreeListRef!IndexingTable(context.settings.headerTableSize);

			// save response converted to HTTP/2
			context.resFrame = alloc.makeArray!ubyte(buildHeaderFrame!(StartLine.RESPONSE)
						(st, headers, context, alloc));
			context.resFrame ~= resBody;

		} ();

		// send response
		switchRes.switchToHTTP2(&handleHTTP2Connection!ConnectionStream, context);
		return true;

	} else {
		// reply with a 400 (bad request) header
		switchRes.sendBadRequest();
		connection.close;
		return false;
	}
}

/** client AND server should send a connection preface
  * server should receive a connection preface from the client + SETTINGS Frame
  * server connection preface consists of a SETTINGS Frame
  */
void handleHTTP2Connection(ConnectionStream)(ConnectionStream stream,
		TCPConnection connection, HTTP2ServerContext context, bool priorKnowledge=false) @safe
	if (isConnectionStream!ConnectionStream || is(ConnectionStream : TLSStreamType))
{
	logTrace("HTTP/2 Connection Handler");

	// read the connection preface
	if(!priorKnowledge) {
		ubyte[24] h2connPreface;
		stream.read(h2connPreface);

		if(h2connPreface != "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") {
			logDebug("Ignoring invalid HTTP/2 client connection preface");
			return;
		}
		logTrace("Received client http2 connection preface");
	}

	// initialize Frame handler
	handleHTTP2FrameChain(stream, connection, context);
}

/* ==================================================== */
/* 					FRAME HANDLING						*/
/* ==================================================== */

/// async frame handler: in charge of closing the connection if no data flows
private void handleHTTP2FrameChain(ConnectionStream)(ConnectionStream stream, TCPConnection
		connection, HTTP2ServerContext context) @safe nothrow
	if (isConnectionStream!ConnectionStream || is(ConnectionStream : TLSStream))
{
	logTrace("HTTP/2 Frame Chain Handler");

	static struct CB {
		ConnectionStream stream;
		TCPConnection connection;
		HTTP2ServerContext context;

		void opCall(bool st)
		{
			if (!st) connection.close;
			else runTask(&handleHTTP2FrameChain, stream, connection, context);
		}
	}

	while(true) {
		try {
			CB cb = {stream, connection, context};
			auto st = connection.waitForDataAsync(cb);

			final switch(st) {
				case WaitForDataAsyncStatus.waiting:
					return;

				case WaitForDataAsyncStatus.noMoreData:
					stream.finalize();
					connection.close();
					return;

				case WaitForDataAsyncStatus.dataAvailable:
					// start the frame handler
					bool close = handleHTTP2Frame(stream, connection, context);

					// determine if this connection needs to be closed
					if(close) {
						logTrace("Closing connection.");
						stream.finalize();
						connection.close();
						return;
					}
			}
		} catch (Exception e) {
			logException(e, "Failed to handle HTTP/2 frame chain");
			connection.close();
			return;
		}
	}
}

/// initializes an allocator and handles stream closing
private bool handleHTTP2Frame(ConnectionStream)(ConnectionStream stream, TCPConnection
		connection, HTTP2ServerContext context) @trusted
	if (isConnectionStream!ConnectionStream || is(ConnectionStream : TLSStream))
{
	import vibe.container.internal.utilallocator: RegionListAllocator;
	logTrace("HTTP/2 Frame Handler");

	bool close = false;

	() @trusted {
		version (VibeManualMemoryManagement)
			scope alloc = new RegionListAllocator!(shared(Mallocator), false)
			(1024, Mallocator.instance);
		else
			scope alloc = new RegionListAllocator!(shared(GCAllocator), true)
				(1024, GCAllocator.instance);

		if(!context.hasMultiplexer) context.multiplexer = FreeListRef!HTTP2Multiplexer(
				alloc,
				context.settings.maxConcurrentStreams,
				context.settings.initialWindowSize,
				context.settings.headerTableSize);

		if(!context.hasTable) context.table = FreeListRef!IndexingTable(context.settings.headerTableSize);

		// create a HTTP/2 Stream
		auto h2stream = HTTP2ConnectionStream!ConnectionStream(stream, 0, alloc);


		close = handleFrameAlloc(h2stream, connection, context, alloc);

		// if stream has to be closed
		if(h2stream.state == HTTP2StreamState.CLOSED) {
			try {
				closeStream(context.multiplexer, h2stream.streamId);
			} catch(Exception e) {
				logWarn("Unable to close stream: " ~ e.msg);
				close = true;
			}
		}
	} ();

	return close;
}

/// used (mixin) to check the validity of the received Frame w.r.to its stream ID
private const string checkvalid = "enforceHTTP2(valid, \"Invalid stream ID\", HTTP2Error.STREAM_CLOSED);";

/** Receives an HTTP2ConnectionStream, and handles the data received by decoding frames
  * Currently supports simple requests / responses
  * Stream Lifecycle is treated according to RFC 7540, Section 5.1
*/
private bool handleFrameAlloc(ConnectionStream)(ref ConnectionStream stream, TCPConnection connection,
		HTTP2ServerContext context, IAllocator alloc) @trusted
{
	logTrace("HTTP/2 Frame Handler (Alloc)");

	uint len = 0;

	// payload buffer
	auto rawBuf = AllocAppender!(ubyte[])(alloc);
	auto payload = AllocAppender!(ubyte[])(alloc);

	// Frame properties
	bool endStream = false;
	bool endHeaders = false;
	bool isAck = false;
	bool close = false;
	scope HTTP2FrameStreamDependency sdep;

	// frame struct
	scope HTTP2FrameHeader header;

/* ==================================================== */
/* 				read received header 					*/
/* ==================================================== */
	if(stream.canRead) {
		try {
			len = stream.readHeader(rawBuf);
		} catch (UncaughtException e) {
			// failed reading from stream, do not close the connection
			stream.state = HTTP2StreamState.CLOSED;
			return false;
		}
	} else {
		// failed reading from stream, do not close the connection
		//stream.state = HTTP2StreamState.CLOSED;
		return false;
	}


	// adjust buffer sizes
	rawBuf.reserve(len);
	payload.reserve(len);

/* ==================================================== */
/* 				read received payload 					*/
/* ==================================================== */
	if(len) stream.readPayload(rawBuf, len);


/* ==================================================== */
/* 				parse received Frame 					*/
/* ==================================================== */
	try {
		header = payload.unpackHTTP2Frame(rawBuf.data, endStream, endHeaders, isAck, sdep);
	} catch (HTTP2Exception e) {
		if (stream.state != HTTP2StreamState.IDLE || stream.streamId == 0) {
			ubyte[GOAWAYFrameLength] f;
			f.buildGOAWAYFrame(stream.streamId, e.code);
			stream.write(f);
			stream.state = HTTP2StreamState.CLOSED;
			logWarn("%s: %s", "Sent GOAWAY Frame", e.message);
			return true;
		} else {
			logDebug("Ignoring unsupported extension header.");
			return false;
		}
	} catch (Exception e) {
		logWarn(e.msg);
	}

/* ==================================================== */
/*    register stream on MUX and determine Frame type	*/
/* ==================================================== */
	try {
		auto valid = registerStream(context.multiplexer, header.streamId);

		logDebug("Received: "~to!string(header.type)~" on streamID "~to!string(header.streamId));

		enforceHTTP2(header.streamId % 2 != 0 || header.streamId == 0, "Clients cannot register even streams", HTTP2Error.PROTOCOL_ERROR);

		if(stream.needsContinuation) enforceHTTP2(header.type == HTTP2FrameType.CONTINUATION,
				"Expected continuation frame", HTTP2Error.PROTOCOL_ERROR);

		stream.streamId = header.streamId;

		final switch(header.type) {
/* ==================================================== */
/* 					DATA Frame (TODO)					*/
/* ==================================================== */
			case HTTP2FrameType.DATA:
				mixin(checkvalid);

				if(endStream) {
					if(stream.state == HTTP2StreamState.HALF_CLOSED_LOCAL) {
						stream.state = HTTP2StreamState.CLOSED;
						closeStream(context.multiplexer, stream.streamId);

					} else if(stream.state == HTTP2StreamState.OPEN) {
						stream.state = HTTP2StreamState.HALF_CLOSED_REMOTE;

					} else if(stream.state == HTTP2StreamState.IDLE) {
						enforceHTTP2(false, "Invalid state", HTTP2Error.PROTOCOL_ERROR);

					} else {
						enforceHTTP2(false, "Stream closed", HTTP2Error.STREAM_CLOSED);
					}
				}
				break;

/* ==================================================== */
/* 					HEADERS Frame 						*/
/* ==================================================== */
			case HTTP2FrameType.HEADERS:
				mixin(checkvalid);
				enforceHTTP2(stream.streamId > 0, "Invalid stream ID", HTTP2Error.PROTOCOL_ERROR);

				stream.state = HTTP2StreamState.OPEN;
				if(sdep.isSet) {
					// update stream dependency with data in `sdep`
				}

				// save the header block for processing
				stream.putHeaderBlock(payload.data);

				if(endStream) {
					stream.state = HTTP2StreamState.HALF_CLOSED_REMOTE;
				}

				// parse headers in payload
				if(endHeaders) {
					logDebug("Received full HEADERS block");
					handleHTTP2HeadersFrame(stream, connection, context, alloc);

				} else {
					// wait for the next CONTINUATION frame until end_headers flag is set
					// END_STREAM flag does not count in this case
					logDebug("Incomplete HEADERS block, waiting for CONTINUATION frame.");
					close = handleFrameAlloc(stream, connection, context, alloc);
				}

				break;

/* ==================================================== */
/* 					PRIORITY Frame (TODO) 				*/
/* ==================================================== */
			case HTTP2FrameType.PRIORITY:
				// do not check validity since PRIORITY frames can be received on CLOSED
				// streams

				enforceHTTP2(stream.streamId > 0, "Invalid stream ID", HTTP2Error.PROTOCOL_ERROR);
				// update stream dependency with data in `sdep`
				break;

/* ==================================================== */
/* 					RST_STREAM Frame					*/
/* ==================================================== */
			case HTTP2FrameType.RST_STREAM:
				enforceHTTP2(stream.state != HTTP2StreamState.IDLE || !valid,
						"Invalid state", HTTP2Error.PROTOCOL_ERROR);

				// reset stream in `closed` state
				if(stream.state != HTTP2StreamState.CLOSED) {
					closeStream(context.multiplexer, stream.streamId);
				}

				logDebug("RST_STREAM: Stream %d closed,  error: %s",
						stream.streamId, cast(HTTP2Error)fromBytes(payload.data,4));
				break;

/* ==================================================== */
/* 					SETTINGS Frame 						*/
/* ==================================================== */
			case HTTP2FrameType.SETTINGS:
				if(!isAck) {
					handleHTTP2SettingsFrame(stream, connection, payload.data, header, context);
				} else {
					enforceHTTP2(payload.data.length == 0,
							"Invalid SETTINGS ACK (payload not empty)", HTTP2Error.FRAME_SIZE_ERROR);
					logDebug("Received SETTINGS ACK");
				}
				break;

/* ==================================================== */
/* 			      PUSH_PROMISE Frame 					*/
/* ==================================================== */
			case HTTP2FrameType.PUSH_PROMISE:
				enforceHTTP2(false,
						"Client should not send PUSH_PROMISE Frames.", HTTP2Error.PROTOCOL_ERROR);
				break;

/* ==================================================== */
/* 				      PING Frame 						*/
/* ==================================================== */
			case HTTP2FrameType.PING:
				if(!isAck) {
					// acknowledge ping with PING ACK Frame
					FixedAppender!(ubyte[], 17) buf;
					buf.createHTTP2FrameHeader(len, header.type, 0x1, header.streamId);

					// write PING Frame header
					stream.write(buf.data);
					// write PING Frame payload (equal to the received one)
					stream.write(payload.data);
					logDebug("Sent PING ACK response");
				}
				break;

/* ==================================================== */
/* 				     GOAWAY Frame 						*/
/* ==================================================== */
			case HTTP2FrameType.GOAWAY:
				logDebug("Received GOAWAY Frame. Closing connection");

				stream.state = HTTP2StreamState.CLOSED;
				closeStream(context.multiplexer, stream.streamId);
				close = true;

				break;

/* ==================================================== */
/* 				     WINDOW_UPDATE Frame 				*/
/* ==================================================== */
			case HTTP2FrameType.WINDOW_UPDATE:
				// can be received on closed streams (in case of pending data)
				enforceHTTP2(stream.state != HTTP2StreamState.IDLE || !valid ||
						stream.streamId == 0, "Invalid state", HTTP2Error.PROTOCOL_ERROR);

				auto inc = fromBytes(payload.data, 4);
				uint maxinc = 1 << 31;
				enforceHTTP2(inc > 0, "Invalid WINDOW_UPDATE increment", HTTP2Error.PROTOCOL_ERROR);

				// connection-based control window must be updated
				auto cw = connectionWindow(context.multiplexer);
				enforceHTTP2(cw + inc < maxinc, "Reached maximum WINDOW size",
						HTTP2Error.FLOW_CONTROL_ERROR);
				updateConnectionWindow(context.multiplexer, cw + inc);

				// per-stream control window must be updated (together with cw)
				if(stream.streamId > 0) {
					auto scw = streamConnectionWindow(context.multiplexer, stream.streamId);
					enforceHTTP2(scw + inc < maxinc, "Reached maximum WINDOW size",
							HTTP2Error.FLOW_CONTROL_ERROR);

					updateStreamConnectionWindow(context.multiplexer, stream.streamId, scw + inc);
				}

				// notify waiting DATA tasks if needed
				if(checkCondition(context.multiplexer, stream.streamId)) {
					logDebug("Notifying stopped tasks");
					notifyCondition(context.multiplexer);
					yield();
				}
				break;

/* ==================================================== */
/* 				     CONTINUATION Frame
/* ==================================================== */
			case HTTP2FrameType.CONTINUATION:
				// must be received immediately after a HEADERS Frame or a
				// CONTINUATION Frame
				enforceHTTP2(stream.state != HTTP2StreamState.IDLE, "Invalid state",
						HTTP2Error.PROTOCOL_ERROR);

				// add the received block to buffer
				stream.putHeaderBlock(payload.data);

				// process header block fragment in payload
				if(endHeaders) {
					logDebug("Received full HEADERS block");
					handleHTTP2HeadersFrame(stream, connection, context, alloc);
				} else {
					logDebug("Incomplete HEADERS block, waiting for CONTINUATION frame.");
					handleFrameAlloc(stream, connection, context, alloc);
				}
				break;
		}

/* ==================================================== */
/* 				  `h2c`: First Response
/* ==================================================== */
		static if(!is(ConnectionStream : TLSStream)) {

			if (context.resFrame) {
				auto l = context.resFrame.takeExactly(3).fromBytes(3) + 9;

				if(l < context.settings.maxFrameSize)
				{
					auto isEndStream = (context.resFrame.length > l) ? 0x0 : 0x1;

					context.resFrame[4] += 0x4 + isEndStream;

					try {
						stream.write(context.resFrame[0..l]);
					} catch (Exception e) {
						logWarn("Unable to write HEADERS Frame to stream");
					}

				} else {
					// TODO CONTINUATION frames
					assert(false);
				}


				auto resBody = context.resFrame[l..$];
				alloc.dispose(context.resFrame);

				// send DATA (body) if present
				// since the first response is part of HTTP/2 initialization,
				// this task is NOT executed asynchronously (for now) TODO
				if(resBody.length > 0) {

					auto dataFrame = AllocAppender!(ubyte[])(alloc);

					// create DATA Frame with END_STREAM (0x1) flag
					if(resBody.length > uint.max) assert(false, "TODO");

					// create DATA frame header
					dataFrame.createHTTP2FrameHeader(cast(uint)resBody.length, HTTP2FrameType.DATA, 0x1, 1);

					// append the DATA body
					dataFrame.put(resBody);

					// try writing data
					try {
						stream.write(dataFrame.data);
					} catch(Exception e) {
						logWarn("Unable to write DATA Frame to stream.");
					}

					logTrace("Sent DATA frame on streamID %s", stream.streamId);

				}

			}
		}

		closeStream(context.multiplexer, stream.streamId);


	} catch(HTTP2Exception e) {
		ubyte[GOAWAYFrameLength] f;
		f.buildGOAWAYFrame(stream.streamId, e.code);
		stream.write(f);
		logWarn("%s: %s", "Sent GOAWAY Frame", e.message);
		stream.state = HTTP2StreamState.CLOSED;
		return true;
	} catch(HPACKException e) {
		ubyte[GOAWAYFrameLength] f;
		f.buildGOAWAYFrame(stream.streamId, HTTP2Error.COMPRESSION_ERROR);
		stream.write(f);
		stream.state = HTTP2StreamState.CLOSED;
		logWarn("%s: %s", "Sent GOAWAY Frame", e.message);
		return true;

	} catch(Exception e) {
		logWarn(e.msg);
	}

	return close;
}
/// process an HEADERS frame
void handleHTTP2HeadersFrame(Stream)(ref Stream stream, TCPConnection connection,
		HTTP2ServerContext context,  IAllocator alloc)
{
	// AllocAppender cannot be used here (TODO discuss)
	auto hdec = appender!(HTTP2HeaderTableField[])();

	// decode headers
	decodeHPACK(cast(immutable(ubyte)[])stream.headerBlock, hdec, context.table, alloc, context.settings.headerTableSize);

	// insert data in table
	hdec.data.each!((h) { if(h.index) context.table.insert(h); });

	// write a response (HEADERS + DATA according to request method)
	handleHTTP2Request(stream, connection, context, hdec.data, context.table, alloc);

	// clean the header block buffer
	stream.resetHeaderBlock();
}

/// handle SETTINGS frame exchange
void handleHTTP2SettingsFrame(Stream)(ref Stream stream, TCPConnection connection, ubyte[] data, HTTP2FrameHeader header, HTTP2ServerContext context) @safe
{
	// parse settings payload
	context.settings.unpackSettings(data);

	// update the connection window and notify waiting workers
	if(stream.streamId == 0) updateConnectionWindow(context.multiplexer, context.settings.initialWindowSize);
	updateStreamConnectionWindow(context.multiplexer, stream.streamId, context.settings.initialWindowSize);

	// notify waiting threads if needed
	if(checkCondition(context.multiplexer, stream.streamId)) {
		logTrace("Notifying stopped tasks");
		notifyCondition(context.multiplexer);
		//yield();
	}

	// acknowledge settings with SETTINGS ACK Frame
	FixedAppender!(ubyte[], 9) ackReply;
	ackReply.createHTTP2FrameHeader(0, header.type, 0x1, header.streamId);

	// new connection: must send a SETTINGS Frame as preface
	if(isConnectionPreface(context.multiplexer)) sendHTTP2SettingsFrame(stream, context);

	// write SETTINGS ACK
	stream.write(ackReply.data);
	logDebug("Sent SETTINGS ACK");
}

/// send a SETTINGS Frame
void sendHTTP2SettingsFrame(Stream)(ref Stream stream, HTTP2ServerContext context) @safe
{
	FixedAppender!(ubyte[], HTTP2HeaderLength+36) settingDst;

	settingDst.createHTTP2FrameHeader(36, HTTP2FrameType.SETTINGS, 0x0, 0);
	settingDst.serializeSettings(context.settings);
	stream.write(settingDst.data);

	logDebug("Sent SETTINGS Frame");
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

/** Represent a HTTP/2 Stream
  * The underlying connection can be TCPConnection or TLSStream
  * TODO: stream dependency, proper handling of stream IDs
  * approach: mantain a union of IDs so that only correct streams are initialized
*/
struct HTTP2ConnectionStream(CS)
{
	static assert(isConnectionStream!CS || is(CS : TLSStream) || isOutputStream!Stream);

	private {
		enum Parse { HEADER, PAYLOAD };
		CS m_conn;
		uint m_streamId;
		Parse toParse = Parse.HEADER;
		HTTP2StreamState m_state;
		AllocAppender!(ubyte[]) m_headerBlock;

		// Stream dependency TODO
		HTTP2FrameStreamDependency m_dependency;
	}

	// embed underlying connection
	alias m_conn this;

	this(CS)(ref CS conn, uint sid, IAllocator alloc) @safe
	{
		m_conn = conn;
		m_streamId = sid;
		m_state = HTTP2StreamState.IDLE;
		m_headerBlock = AllocAppender!(ubyte[])(alloc);
	}

	this(CS)(ref CS conn, IAllocator alloc) @safe
	{
		this(conn, 0, alloc);
	}

	@property CS connection() @safe { return m_conn; }

	@property HTTP2StreamState state() @safe @nogc { return m_state; }

	@property bool canRead() @safe @nogc
	{
		return (m_state == HTTP2StreamState.OPEN || m_state == HTTP2StreamState.IDLE);
	}

	/// set state according to Stream lifecycle (RFC 7540 section 5.1)
	@property void state(HTTP2StreamState st) @safe
	{
		switch(st) {
			// allowed: IDLE -> OPEN
			//          OPEN -> OPEN
			case HTTP2StreamState.OPEN:
				if(m_state == HTTP2StreamState.IDLE ||
						m_state == HTTP2StreamState.OPEN)
					m_state = st;
				else enforceHTTP2(false, "Invalid state", HTTP2Error.PROTOCOL_ERROR);
				break;

			// allowed: OPEN -> HCLOCAL
			// 			RESERVED_REMOTE -> HCLOCAL
			// 			HCLOCAL -> HCLOCAL
			case HTTP2StreamState.HALF_CLOSED_LOCAL:
				if(m_state == HTTP2StreamState.OPEN ||
						m_state == HTTP2StreamState.RESERVED_REMOTE ||
						m_state == HTTP2StreamState.HALF_CLOSED_LOCAL)
					m_state = st;
				else enforceHTTP2(false, "Invalid state", HTTP2Error.PROTOCOL_ERROR);
				break;

			// allowed: OPEN -> HCREMOTE
			// 			RESERVED_LOCAL -> HCREMOTE
			// 			HCREMOTE -> HCREMOTE
			case HTTP2StreamState.HALF_CLOSED_REMOTE:
				if(m_state == HTTP2StreamState.OPEN ||
						m_state == HTTP2StreamState.RESERVED_LOCAL ||
						m_state == HTTP2StreamState.HALF_CLOSED_REMOTE)
					m_state = st;
				else enforceHTTP2(false, "Invalid state", HTTP2Error.PROTOCOL_ERROR);
				break;

			// allowed: all transitions to CLOSED
			//	(RST_STREAM, GOAWAY permit this)
			case HTTP2StreamState.CLOSED:
				m_state = st;
				break;

			// specific to PUSH_PROMISE Frames
			case HTTP2StreamState.RESERVED_LOCAL:
			case HTTP2StreamState.RESERVED_REMOTE:
				if(m_state == HTTP2StreamState.IDLE) m_state = st;
				else enforceHTTP2(false, "Invalid state", HTTP2Error.PROTOCOL_ERROR);
				break;

			default:
				enforceHTTP2(false, "Invalid state", HTTP2Error.PROTOCOL_ERROR);
 		}
		logTrace("Stream: %d state: %s", m_streamId, st);
	}

	@property uint streamId() @safe @nogc { return m_streamId; }

	@property void streamId(uint sid) @safe @nogc { m_streamId = sid; }

	@property HTTP2FrameStreamDependency dependency() @safe @nogc { return m_dependency; }

	@property ubyte[] headerBlock() @safe
	{
		assert(!m_headerBlock.data.empty, "No data in header block buffer");
		return m_headerBlock.data;
	}

	@property bool needsContinuation() @safe
	{
		return !m_headerBlock.data.empty;
	}

	/// reads from stream a frame header
	uint readHeader(R)(ref R dst) @safe
	{
		assert(toParse == Parse.HEADER);

		ubyte[HTTP2HeaderLength] buf; // should always be 9

		m_conn.read(buf);
		dst.put(buf);

		// length of payload
		auto len = dst.data[0..3].fromBytes(3);
		if(len > 0) toParse = Parse.PAYLOAD;

		return len;
	}

	/// reads from stream a frame payload
	void readPayload(R)(ref R dst, int len) @safe
	{
		assert(toParse == Parse.PAYLOAD);
		toParse = Parse.HEADER;

		ubyte[8] buf = void;

		/// perform multiple reads until payload is over (@nogc compatibility)
		while(len > 0) {
			auto end = (len < buf.length) ? len : buf.length;
			len -= m_conn.read(buf[0..end], IOMode.all);
			dst.put(buf[0..end]);
		}
	}

	/// save a HEADERS / CONTINUATION block for processing
	void putHeaderBlock(T)(T src) @safe
		if(isInputRange!T && is(ElementType!T : ubyte))
	{
		m_headerBlock.put(src);
	}

	void resetHeaderBlock() @trusted
	{
		m_headerBlock.reset(AppenderResetMode.freeData);
	}

	void finalize() @safe { }
}

unittest {
	import vibe.core.core : runApplication;
	// empty handler, just to test if protocol switching works
	void handleReq(scope HTTPServerRequest req, scope HTTPServerResponse res)
	@safe {
		if (req.path == "/")
			res.writeBody("Hello, World! This response is sent through HTTP/2");
	}

	auto settings = new HTTPServerSettings();
	settings.port = 8090;
	settings.bindAddresses = ["localhost"];

	listenHTTP(settings, &handleReq);
	//runApplication();
}

unittest {
	import vibe.core.core : runApplication;

	void handleRequest(scope HTTPServerRequest req, scope HTTPServerResponse res)
	@safe {
		if (req.path == "/")
			res.writeBody("Hello, World! This response is sent through HTTP/2\n");
	}


	auto settings = new HTTPServerSettings;
	settings.port = 8091;
	settings.bindAddresses = ["127.0.0.1", "192.168.1.131"];
	settings.tlsContext = createTLSContext(TLSContextKind.server);
	settings.tlsContext.useCertificateChainFile("tests/server.crt");
	settings.tlsContext.usePrivateKeyFile("tests/server.key");

	// set alpn callback to support HTTP/2
	// should accept the 'h2' protocol request
	settings.tlsContext.alpnCallback(http2Callback);

	// dummy, just for testing
	listenHTTP(settings, &handleRequest);
	//runApplication();
}

