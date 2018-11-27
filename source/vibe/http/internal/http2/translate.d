module vibe.http.internal.http2.translate;

import vibe.http.internal.http2.settings;
import vibe.http.internal.http2.http2 : HTTP2ConnectionStream;
import vibe.http.internal.http2.hpack.hpack;
import vibe.http.internal.http2.hpack.tables;
import vibe.http.internal.http2.frame;

import vibe.http.common;
import vibe.http.status;
import vibe.http.server;
import vibe.core.log;
import vibe.core.stream;
import vibe.internal.interfaceproxy;
import vibe.stream.tls;
import vibe.internal.allocator;
import vibe.internal.array;
import vibe.internal.utilallocator: RegionListAllocator;
import vibe.stream.wrapper : ConnectionProxyStream, createConnectionProxyStream, createConnectionProxyStreamFL;
import vibe.utils.string;
import vibe.inet.url;

import std.range;
import std.string;
import std.conv;
import std.traits;
import std.typecons;
import std.datetime;
import std.exception;
import std.algorithm.iteration;
import std.algorithm.mutation;
import std.algorithm.searching;

/**
  * Translation between HTTP/1.1 and HTTP/2 headers, as documented in:
  * RFC 7540 (HTTP/2) section 8
*/

enum StartLine { REQUEST, RESPONSE };

private alias H2F = HTTP2HeaderTableField;

/// accepts a HTTP/1.1 header list, converts it to an HTTP/2 header frame and encodes it
ubyte[] buildHeaderFrame(alias type)(string[] h1header, HTTP2ServerContext context, ref IndexingTable table, scope IAllocator alloc) @safe
{
	// frame header + frame payload
	FixedAppender!(ubyte[], 9) hbuf;
	auto pbuf = AllocAppender!(ubyte[])(alloc);
	auto res = AllocAppender!(ubyte[])(alloc);

	// split the start line of each req / res into pseudo-headers
	convertStartMessage(h1header[0], pbuf, table, type, context.isTLS);
	h1header.popFront();

	// convert and encode the range of headers from HTTP1 to HTTP2
	h1header
		.map!(s => s.strip('\n').replace("Host", ":authority").toLower)
		.filter!(s => !s.empty)
		.each!(s => s.split(": ").H2F.encodeHPACK(pbuf, table));

	// TODO padding
	hbuf.createHTTP2FrameHeader(cast(uint)pbuf.data.length, HTTP2FrameType.SETTINGS, 0x4, 0);
	res.put(hbuf.data);
	res.put(pbuf.data);
	return res.data;
}
/// DITTO
ubyte[] buildHeaderFrame(alias type)(string h1header, HTTP2ServerContext context, ref IndexingTable table, scope IAllocator alloc) @safe
{
	return buildHeaderFrame!type(h1header.split('\r'), context, table, alloc);
}

/// generates an HTTP/2 pseudo-header representation to encode a HTTP/1.1 start message line
private void convertStartMessage(T)(string src, ref T dst, ref IndexingTable table, StartLine type, bool isTLS = true) @safe
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
	src.splitter(' ').each!(s => toPseudo(s));
}

unittest {
	import std.experimental.allocator;
	import std.experimental.allocator.mallocator;
	HTTP2Settings settings;
	HTTPServerContext ctx;
	auto context = HTTP2ServerContext(ctx, settings);
	context.setNoTLS();
	auto table = IndexingTable(settings.headerTableSize);
	scope alloc = new RegionListAllocator!(shared(Mallocator), false)(1024, Mallocator.instance);

	string header = "GET / HTTP/2\r\nHost: www.example.com\r\n";
	ubyte[] expected = [0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1 , 0xe3, 0xc2 , 0xe5, 0xf2 , 0x3a, 0x6b , 0xa0, 0xab , 0x90, 0xf4 , 0xff];
	// [9..$] excludes the HTTP/2 Frame header
	auto res = buildHeaderFrame!(StartLine.REQUEST)(header, context, table, alloc)[9..$];
	assert(res == expected);

	string resHeader = "HTTP/2 200 OK";
	expected = [0x88];
	res = buildHeaderFrame!(StartLine.RESPONSE)(resHeader, context, table, alloc)[9..$];

	assert(res == expected);
}

// similar to originalHandleRequest but adapted to HTTP/2
bool handleHTTP2Request(UStream)(HTTP2ConnectionStream!UStream stream, TCPConnection tcp_connection,
		HTTP2ServerContext h2context, HTTP2HeaderTableField[] headers, ref IndexingTable table, scope IAllocator alloc) @safe
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

	// temporarily set to the default settings, the virtual host specific settings will be set further down
	req.m_settings = settings;

	// Create the response object
	InterfaceProxy!ConnectionStream cproxy = tcp_connection;
	InterfaceProxy!Stream cstream = stream.connection; // TCPConnection / TLSStream
	auto res = HTTPServerResponse(cstream, cproxy, settings, alloc);
	// check for TLS encryption
	auto istls = h2context.isTLS;
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

	// TODO error page handler

	bool parsed = false;

	// parse request:
	// both status line + headers (already unpacked in `headers`)
	// defined in vibe.http.server because of protected struct HTTPServerRequest
	parseHTTP2RequestHeader(headers, req);

	//try {
		// find the matching virtual host
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
			if (icmp2(*pv, "100-continue") == 0) {
				logTrace("sending 100 continue");
				auto cres =	buildHeaderFrame!(StartLine.RESPONSE)(
						"HTTP/1.1 100 Continue\r\n\r\n", h2context, table, alloc);
				// TODO return / send header
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

		// handle the request
		//logTrace("handle request (body %d)", req.bodyReader.leastSize);

		res.httpVersion = req.httpVersion;
		request_task(req, res);

		// if no one has written anything, return 404
		if (!res.headerWritten) {
			//string dbg_msg;
			//logDiagnostic("No response written for %s", req.requestURI);
			//if (settings.options & HTTPServerOption.errorStackTraces)
				//dbg_msg = format("No routes match path '%s'", req.requestURI);
			//errorOut(HTTPStatus.notFound, httpStatusText(HTTPStatus.notFound), dbg_msg, null);
		}
	//} catch (HTTPStatusException err) {
		//if (!res.headerWritten) errorOut(err.status, err.msg, err.debugMessage, err);
		//else logDiagnostic("HTTPSterrorOutatusException while writing the response: %s", err.msg);
		//debug logDebug("Exception while handling request %s %s: %s", req.method, req.requestURI, () @trusted { return err.toString().sanitize; } ());
		//if (!parsed || res.headerWritten || justifiesConnectionClose(err.status))
			//keep_alive = false;
	//} catch (UncaughtException e) {
		//auto status = parsed ? HTTPStatus.internalServerError : HTTPStatus.badRequest;
		//string dbg_msg;
		//if (settings.options & HTTPServerOption.errorStackTraces) dbg_msg = () @trusted { return e.toString().sanitize; } ();
		//if (!res.headerWritten && tcp_connection.connected) errorOut(status, httpStatusText(status), dbg_msg, e);
		//else logDiagnostic("Error while writing the response: %s", e.msg);
		//debug logDebug("Exception while handling request %s %s: %s", req.method, req.requestURI, () @trusted { return e.toString().sanitize(); } ());
		//if (!parsed || res.headerWritten || !cast(Exception)e) keep_alive = false;
	//}

	return true;
}













































