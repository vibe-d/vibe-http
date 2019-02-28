module vibe.http.internal.http2.exchange;

import vibe.http.internal.http2.multiplexing;
import vibe.http.internal.http2.settings;
import vibe.http.internal.http2.http2 : HTTP2ConnectionStream, HTTP2StreamState;
import vibe.http.internal.http2.hpack.hpack;
import vibe.http.internal.http2.hpack.tables;
import vibe.http.internal.http2.frame;

import vibe.http.common;
import vibe.http.status;
import vibe.http.server;
import vibe.core.log;
import vibe.core.stream;
import vibe.core.core; 
import vibe.internal.interfaceproxy;
import vibe.stream.tls;
import vibe.internal.allocator;
import vibe.internal.array;
import vibe.internal.utilallocator: RegionListAllocator;
import vibe.stream.wrapper : ConnectionProxyStream, createConnectionProxyStream, createConnectionProxyStreamFL;
import vibe.utils.string;
import vibe.stream.memory;
import vibe.inet.url;
import vibe.inet.message;

import std.range;
import std.string;
import std.conv;
import std.traits;
import std.typecons;
import std.datetime;
import std.exception;
import std.format;
import std.algorithm.iteration;
import std.algorithm.mutation;
import std.algorithm.searching;
import std.algorithm.comparison;

/**
  * HTTP/2 message exchange module as documented in:
  * RFC 7540 (HTTP/2) section 8
*/

enum StartLine { REQUEST, RESPONSE };

private alias H2F = HTTP2HeaderTableField;

alias DataOutputStream = MemoryOutputStream;

/// accepts a HTTP/1.1 header list, converts it to an HTTP/2 header frame and encodes it
ubyte[] buildHeaderFrame(alias type)(string statusLine, InetHeaderMap headers,
		HTTP2ServerContext context, IndexingTable* table, scope IAllocator alloc, bool
		isTLS = true) @safe
{
	// frame header + frame payload
	FixedAppender!(ubyte[], 9) hbuf;
	auto pbuf = AllocAppender!(ubyte[])(alloc);
	auto res = AllocAppender!(ubyte[])(alloc);

	// split the start line of each req / res into pseudo-headers
	convertStartMessage(statusLine, pbuf, table, type, isTLS);

	// "Host" header does not exist in HTTP/2, use ":authority" pseudo-header
	if("Host" in headers) {
		headers[":authority"] = headers["Host"];
		headers.remove("Host");
	}

	foreach(k,v; headers) {
		H2F(k.toLower,v).encodeHPACK(pbuf, table);
	}

	// TODO padding
	if(context.next_sid == 0) context.next_sid = 1;

	hbuf.createHTTP2FrameHeader(cast(uint)pbuf.data.length, HTTP2FrameType.HEADERS, 0x0, context.next_sid);

	res.put(hbuf.data);
	res.put(pbuf.data);
	return res.data;
}

/// DITTO for first request in case of h2c
ubyte[] buildHeaderFrame(alias type)(string statusLine, InetHeaderMap headers,
		HTTP2ServerContext context, scope IAllocator alloc) @trusted
{
	return buildHeaderFrame!type(statusLine, headers, context, context.table, alloc);
}

/// generates an HTTP/2 pseudo-header representation to encode a HTTP/1.1 start message line
private void convertStartMessage(T)(string src, ref T dst, IndexingTable* table, StartLine type, bool isTLS = true) @safe
{
	void toPseudo(string buf) @safe
	{
		// exclude protocol version (not needed in HTTP/2)
		if(buf != "HTTP/1.1" && buf != "HTTP/2")
		{
			if(type == StartLine.REQUEST) { // request
				//	request-line = method SP request-target SP HTTP-version CRLF
					try {
						auto method = httpMethodFromString(buf);
						H2F(":method", method).encodeHPACK(dst, table);
					} catch(Exception e) {
						H2F(":scheme", (isTLS ? "https" : "http")).encodeHPACK(dst, table);
						H2F(":path", buf).encodeHPACK(dst, table);
				}
			} else if(type == StartLine.RESPONSE) { // response (status-line)
				// status-line = HTTP-version SP status-code SP reason-phrase CRLF
				static foreach(st; __traits(allMembers, HTTPStatus)) {
					if(buf.isNumeric && __traits(getMember, HTTPStatus, st) == buf.to!int) {
						mixin("H2F(\":status\",HTTPStatus."~st~").encodeHPACK(dst, table); return;");
					}
				}
			}
		}
	}

	// consider each chunk of the start message line
	src.strip("\r\n").splitter(' ').each!(s => toPseudo(s));
}

unittest {
	import std.experimental.allocator;
	import std.experimental.allocator.mallocator;
	HTTP2Settings settings;
	HTTPServerContext ctx;
	auto context = HTTP2ServerContext(ctx, settings);
	auto table = new IndexingTable(settings.headerTableSize);
	scope alloc = new RegionListAllocator!(shared(Mallocator), false)(1024, Mallocator.instance);

	string statusline = "GET / HTTP/2\r\n\r\n";
	InetHeaderMap hmap;
	hmap["Host"] = "www.example.com";
	ubyte[] expected = [0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1 , 0xe3, 0xc2 , 0xe5, 0xf2 , 0x3a, 0x6b , 0xa0, 0xab , 0x90, 0xf4 , 0xff];
	// [9..$] excludes the HTTP/2 Frame header
	auto res = buildHeaderFrame!(StartLine.REQUEST)(statusline, hmap, context, table, alloc,
			false)[9..$];
	assert(res == expected);

	statusline = "HTTP/2 200 OK";
	InetHeaderMap hmap1;
	expected = [0x88];
	res = buildHeaderFrame!(StartLine.RESPONSE)(statusline, hmap1, context, table, alloc,
			false)[9..$];

	assert(res == expected);
}

/* ======================================================= */
/* 					HTTP/2 REQUEST HANDLING 			   */
/* ======================================================= */

/** Similar to originalHandleRequest, adapted to HTTP/2
  * The request is converted to HTTPServerRequest through parseHTTP2RequestHeader
  * once the HTTPServerResponse is built, HEADERS frame and (optionally) DATA Frames are sent
*/
bool handleHTTP2Request(UStream)(ref HTTP2ConnectionStream!UStream stream, TCPConnection tcp_connection, HTTP2ServerContext h2context, HTTP2HeaderTableField[] headers, IndexingTable* table, scope IAllocator alloc) @safe
{
	SysTime reqtime = Clock.currTime(UTC());
	HTTPServerContext listen_info = h2context.h1context;

	// initialize request
	auto req = HTTPServerRequest(reqtime, listen_info.bindPort);

	// store the IP address
	req.clientAddress = tcp_connection.remoteAddress;

	if (!listen_info.hasVirtualHosts) {
		logWarn("Didn't find a HTTP listening context for incoming connection. Dropping.");
		return false;
	}

	// Default to the first virtual host for this listener
	HTTPServerContext.VirtualHost context = listen_info.virtualHosts[0];
	HTTPServerRequestDelegate request_task = context.requestHandler;
	HTTPServerSettings settings = context.settings;

	// temporarily set to the default settings
	req.m_settings = settings;

	// Create the response object
	InterfaceProxy!ConnectionStream cproxy = tcp_connection;
	InterfaceProxy!Stream cstream = stream.connection; // TCPConnection / TLSStream
	auto res = HTTPServerResponse(cstream, cproxy, settings, alloc);

	// check for TLS encryption
	bool istls;
	static if(is(UStream : TLSStream)) {
		istls = true;
	} else {
		istls = false;
	}
	req.tls = istls;
	res.tls = istls;

	if (req.tls) {
		version (HaveNoTLS) assert(false);
		else {
			static if (is(InterfaceProxy!Stream == Stream))
				req.clientCertificate = (cast(TLSStream)stream.connection).peerCertificate;
			else static if (is(typeof(stream.connection) : TLSStream))
				req.clientCertificate = stream.connection.peerCertificate;
			else
				assert(false);
		}
	}

	bool parsed = false;

	// parse request:
	// both status line + headers (already unpacked in `headers`)
	// defined in vibe.http.server because of protected struct HTTPServerRequest
	parseHTTP2RequestHeader(headers, req);
	if(req.host.empty) {
		req.host = tcp_connection.localAddress.toString;
		req.requestURI = req.host ~ req.path;
	}

	string reqhost;
	ushort reqport = 0;
	{
		string s = req.host;
		enforceHTTP(s.length > 0 || req.httpVersion <= HTTPVersion.HTTP_1_0, HTTPStatus.badRequest, "Missing Host header.");
		if (s.startsWith('[')) { // IPv6 address
			auto idx = s.indexOf(']');
			enforce(idx > 0, "Missing closing ']' for IPv6 address.");
			reqhost = s[1 .. idx];
			s = s[idx+1 .. $];
		} else if (s.length) { // host name or IPv4 address
			auto idx = s.indexOf(':');
			if (idx < 0) idx = s.length;
			enforceHTTP(idx > 0, HTTPStatus.badRequest, "Missing Host header.");
			reqhost = s[0 .. idx];
			s = s[idx .. $];
		}
		if (s.startsWith(':')) reqport = s[1 .. $].to!ushort;
	}
	foreach (ctx; listen_info.virtualHosts) {
		if (icmp2(ctx.settings.hostName, reqhost) == 0 &&
				(!reqport || reqport == ctx.settings.port))
		{
			context = ctx;
			settings = ctx.settings;
			request_task = ctx.requestHandler;
			break;
		}
	}
	req.m_settings = settings;
	res.m_settings = settings;

	// setup compressed output
	if (settings.useCompressionIfPossible) {
		if (auto pae = "Accept-Encoding" in req.headers) {
			if (canFind(*pae, "gzip")) {
				res.headers["Content-Encoding"] = "gzip";
			} else if (canFind(*pae, "deflate")) {
				res.headers["Content-Encoding"] = "deflate";
			}
		}
	}

	// handle Expect header
	if (auto pv = "Expect" in req.headers) {
		assert(false); // TODO determine if actually used with HTTP/2 (PUSH_PROMISE?)
		if (icmp2(*pv, "100-continue") == 0) {
			logTrace("sending 100 continue");
			InetHeaderMap hmap;
			auto cres =	buildHeaderFrame!(StartLine.RESPONSE)(
					"HTTP/1.1 100 Continue\r\n\r\n", hmap, h2context, table, alloc, istls);
		}
	}

	// eagerly parse the URL as its lightweight and defacto @nogc
	auto url = URL.parse(req.requestURI);
	req.queryString = url.queryString;
	req.username = url.username;
	req.password = url.password;
	req.requestPath = url.path;

	// lookup the session
	if (settings.sessionStore) {
		// use the first cookie that contains a valid session ID in case
		// of multiple matching session cookies
		foreach (val; req.cookies.getAll(settings.sessionIdCookie)) {
			req.session = settings.sessionStore.open(val);
			res.m_session = req.session;
			if (req.session) break;
		}
	}

	// write default headers
	if (req.method == HTTPMethod.HEAD) res.m_isHeadResponse = true;
	if (settings.serverString.length)
		res.headers["Server"] = settings.serverString;
	res.headers["Date"] = formatRFC822DateAlloc(alloc, reqtime);
	if (req.persistent) res.headers["Keep-Alive"] = formatAlloc(alloc, "timeout=%d", settings.keepAliveTimeout.total!"seconds"());

	// finished parsing the request
	parsed = true;
	logTrace("persist: %s", req.persistent);
	//keep_alive = req.persistent;
	logDebug("Received %s request on stream ID %d", req.method, stream.streamId);

	// utility to format the status line
	auto statusLine = AllocAppender!string(alloc);

	void writeLine(T...)(string fmt, T args)
		@safe {
			formattedWrite(() @trusted { return &statusLine; } (), fmt, args);
			statusLine.put("\r\n");
			logTrace(fmt, args);
		}

	// header frame to be sent
	ubyte[] headerFrame;

	// handle payload (DATA frame)
	auto dataWriter = createDataOutputStream(alloc);
	res.bodyWriterH2 = dataWriter;
	h2context.next_sid = stream.streamId;

	// run task (writes body)
	request_task(req, res);

	if(req.method != HTTPMethod.HEAD && dataWriter.data.length > 0) { // HEADERS + DATA

		// write the status line
		writeLine("%s %d %s",
				getHTTPVersionString(res.httpVersion),
				res.statusCode,
				res.statusPhrase.length ? res.statusPhrase : httpStatusText(res.statusCode));

		// build the HEADERS frame
		() @trusted {
			headerFrame = buildHeaderFrame!(StartLine.RESPONSE)(statusLine.data, res.headers,
					h2context, table, alloc, istls);
		} ();

		// send HEADERS frame
		if(headerFrame.length < h2context.settings.maxFrameSize) {
			headerFrame[4] += 0x4; // set END_HEADERS flag (sending complete header)
			cstream.write(headerFrame);

		} else {
			// TODO CONTINUATION frames
			assert(false);
		}

		logDebug("Sent HEADERS frame on streamID " ~ stream.streamId.to!string);

		auto tlen = dataWriter.data.length;

		// multiple DATA Frames might be required
		void sendDataTask()
		@safe {
			logDebug("[DATA] Starting dispatch task");

			scope(exit) {
				if(stream.state == HTTP2StreamState.HALF_CLOSED_REMOTE) {
					stream.state = HTTP2StreamState.CLOSED;
				} else {
					stream.state = HTTP2StreamState.HALF_CLOSED_LOCAL;
				}
			}

			try {

				auto abort = false;
				ulong done = 0;

				// window length
				uint wlen = sendWindowLength(h2context.multiplexerID,
						stream.streamId, h2context.settings.maxFrameSize, tlen);

				// until the whole payload is sent
				while(done <= tlen) {
					auto dataFrame = AllocAppender!(ubyte[])(alloc);

					dataFrame.createHTTP2FrameHeader(
								wlen,
								HTTP2FrameType.DATA,
								(done+wlen >= tlen) ? 0x1 : 0x0, // END_STREAM 0x1
								stream.streamId
							);

					// send is over
					if(done == tlen) {
						logDebug("[DATA] Completed DATA frame dispatch");
						// remove task from waiting state
						doneCondition(h2context.multiplexerID, stream.streamId);
						closeStream(h2context.multiplexerID, stream.streamId);
						break;
					}

					// wait to resume and retry
					if(wlen == 0) {
						logDebug("[DATA] Dispatch task waiting for WINDOW_UPDATE");

						// after 60 seconds waiting, terminate dispatch
						() @trusted {
							auto timer = setTimer(60.seconds, {
									logDebug("[DATA] timer expired, aborting dispatch");
									notifyCondition(h2context.multiplexerID);
									abort = true;
									});

							// wait until a new WINDOW_UPDATE is received (or timer expires)
							waitCondition(h2context.multiplexerID, stream.streamId);

							// task resumed: cancel timer
							if(!abort) timer.stop;
							else return;
						} ();

						logDebug("[DATA] Dispatch task resumed");

					} else {
						// write

						dataFrame.put(dataWriter.data[done..done+wlen]);
						cstream.write(dataFrame.data);

						done += wlen;

						logDebug("[DATA] Sent frame chunk (%d/%d bytes) on streamID %d",
								done, tlen, stream.streamId);

						updateWindow(h2context.multiplexerID, stream.streamId, wlen);
					}

					// compute new window length
					wlen = sendWindowLength(h2context.multiplexerID,
							stream.streamId, h2context.settings.maxFrameSize, tlen - done);
				}

			} catch (Exception e) {
				return;
			}
		}

		// spawn the asynchronous data sender
		runTask(&sendDataTask);

	} else if(dataWriter.data.length > 0) { // HEAD response, HEADERS frame, no DATA

		// write the status line
		writeLine("%s %d %s",
				getHTTPVersionString(res.httpVersion),
				res.statusCode,
				res.statusPhrase.length ? res.statusPhrase : httpStatusText(res.statusCode));

		// build the HEADERS frame
		() @trusted {
			headerFrame = buildHeaderFrame!(StartLine.RESPONSE)(statusLine.data, res.headers,
					h2context, table, alloc, istls);
		} ();

		// send HEADERS frame
		if(headerFrame.length < h2context.settings.maxFrameSize) {
			headerFrame[4] += 0x5; // set END_HEADERS, END_STREAM flag
			cstream.write(headerFrame);
		} else {
			// TODO CONTINUATION frames
			assert(false);
		}

		logDebug("Sent HEADERS frame on streamID " ~ stream.streamId.to!string);

		logDebug("[Data] No DATA frame to send");

		if(stream.state == HTTP2StreamState.HALF_CLOSED_REMOTE) {
			stream.state = HTTP2StreamState.CLOSED;
		} else {
			stream.state = HTTP2StreamState.HALF_CLOSED_LOCAL;
		}
		closeStream(h2context.multiplexerID, stream.streamId);

	} else { // 404: no DATA for the given path

		writeLine("%s %d %s",
				"HTTP/2",
				404,
				"Not Found");

		// build the HEADERS frame
		() @trusted {
			headerFrame = buildHeaderFrame!(StartLine.RESPONSE)(statusLine.data, res.headers,
					h2context, table, alloc, istls);
		} ();

		if(headerFrame.length < h2context.settings.maxFrameSize) {
			headerFrame[4] += 0x5; // set END_HEADERS, END_STREAM flag
			cstream.write(headerFrame);
		}

		logDebug("No response: sent 404 HEADERS frame");

	}

	return true;
}


uint sendWindowLength(const string idx, const uint sid, const uint maxfsize, const ulong len) @safe
{
	return min(connectionWindow(idx), streamConnectionWindow(idx,sid), maxfsize, len);
}

void updateWindow(const string idx, const uint sid, const ulong sent) @safe
{
	auto cw = connectionWindow(idx) - sent;
	auto scw = streamConnectionWindow(idx, sid) - sent;

	updateConnectionWindow(idx, cw);
	updateStreamConnectionWindow(idx, sid, cw);
}

private DataOutputStream createDataOutputStream(IAllocator alloc = vibeThreadAllocator())
@safe nothrow {
	return createMemoryOutputStream(alloc);
}

private HeaderOutputStream createHeaderOutputStream(IAllocator alloc = vibeThreadAllocator())
@safe nothrow {
    return new HeaderOutputStream(alloc);
}

private final class HeaderOutputStream : OutputStream {
@safe:

    private {
        AllocAppender!(string) m_destination;
    }

    this(IAllocator alloc)
    nothrow {
        m_destination = AllocAppender!(string)(alloc);
    }

    /// An array with all data written to the stream so far.
    @property string data() @trusted nothrow { return m_destination.data(); }

    /// Resets the stream to its initial state containing no data.
    void reset(AppenderResetMode mode = AppenderResetMode.keepData)
    @system {
        m_destination.reset(mode);
    }

    /// Reserves space for data - useful for optimization.
    void reserve(size_t nbytes)
    {
        m_destination.reserve(nbytes);
    }

    size_t write(in string bytes, IOMode)
    {
        () @trusted { m_destination.put(bytes); } ();
        return bytes.length;
	}
	/// DITTO
    size_t write(const(ubyte[]) bytes, IOMode)
    {
        () @trusted { m_destination.put(cast(string)bytes); } ();
        return bytes.length;
	}

    alias write = OutputStream.write;

    void flush()
    nothrow {
    }

    void finalize()
    nothrow {
    }
}
