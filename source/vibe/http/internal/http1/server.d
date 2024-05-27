/**
	A HTTP 1.1/1.0 server implementation.

	Copyright: © 2012-2024 Sönke Ludwig
	License: Subject to the terms of the MIT license, as written in the included LICENSE.txt file.
	Authors: Sönke Ludwig, Jan Krüger, Ilya Shipunov
*/
module vibe.http.internal.http1.server;

import vibe.container.internal.appender : FixedAppender;
import vibe.core.log;
import vibe.core.net;
import vibe.core.stream;
import vibe.http.common;
import vibe.http.server;
import vibe.inet.message;
import vibe.inet.url;
import vibe.internal.freelistref;
import vibe.internal.string : formatAlloc, icmp2;

import core.time;
import std.datetime : Clock, SysTime, UTC;
import std.encoding : sanitize;
import std.exception : enforce;
import std.format : format;


/** Treats an existing connection as an HTTP connection and processes incoming
	requests.

	After all requests have been processed, the connection will be closed and
	the function returns to the caller.

	Params:
		connection = The stream to treat as an incoming HTTP client connection.
		context = Information about the incoming listener and available
			virtual hosts
*/
void handleHTTP1Connection(TLSStreamType)(TCPConnection connection, TLSStreamType tls_stream, StreamProxy http_stream, HTTPServerContext context)
@safe {

	while (!connection.empty) {
		HTTPServerSettings settings;
		bool keep_alive;

		version(HaveNoTLS) {} else {
			// handle oderly TLS shutdowns
			if (tls_stream && tls_stream.empty) break;
		}

		() @trusted {
			scope request_allocator = createRequestAllocator();
			scope (exit) freeRequestAllocator(request_allocator);

			handleRequest!TLSStreamType(http_stream, connection, context, settings, keep_alive, request_allocator);
		} ();
		if (!keep_alive) { logTrace("No keep-alive - disconnecting client."); break; }

		logTrace("Waiting for next request...");
		// wait for another possible request on a keep-alive connection
		if (!connection.waitForData(settings.keepAliveTimeout)) {
			if (!connection.connected) logTrace("Client disconnected.");
			else logDebug("Keep-alive connection timed out!");
			break;
		}
	}
}


private bool handleRequest(TLSStreamType, Allocator)(StreamProxy http_stream, TCPConnection tcp_connection, HTTPServerContext listen_info, ref HTTPServerSettings settings, ref bool keep_alive, scope Allocator request_allocator)
@safe {
	import std.algorithm.searching : canFind, startsWith;
	import std.conv : parse, to;
	import std.string : indexOf;
	import vibe.core.file : existsFile, removeFile;

	SysTime reqtime = Clock.currTime(UTC());

	// some instances that live only while the request is running
	FreeListRef!HTTPServerRequest req = FreeListRef!HTTPServerRequest(reqtime, listen_info.bindPort);
	FreeListRef!TimeoutHTTPInputStream timeout_http_input_stream;
	FreeListRef!LimitedHTTPInputStream limited_http_input_stream;
	FreeListRef!ChunkedInputStream chunked_input_stream;

	// store the IP address
	req.clientAddress = tcp_connection.remoteAddress;

	if (!listen_info.hasVirtualHosts) {
		logWarn("Didn't find a HTTP listening context for incoming connection. Dropping.");
		keep_alive = false;
		return false;
	}

	// Default to the first virtual host for this listener
	HTTPServerContext.VirtualHost context = listen_info.m_virtualHosts[0];
	HTTPServerRequestDelegate request_task = context.requestHandler;
	settings = context.settings;

	// temporarily set to the default settings, the virtual host specific settings will be set further down
	req.m_settings = settings;

	// Create the response object
	ConnectionStreamProxy cproxy = tcp_connection;
	auto res = FreeListRef!HTTPServerResponse(http_stream, cproxy, settings, request_allocator/*.Scoped_payload*/);
	req.tls = res.m_tls = listen_info.tlsContext !is null;
	if (req.tls) {
		version (HaveNoTLS) assert(false);
		else {
			static if (is(InterfaceProxy!ConnectionStream == ConnectionStream))
				req.clientCertificate = (cast(TLSStream)http_stream).peerCertificate;
			else
				req.clientCertificate = http_stream.extract!TLSStreamType.peerCertificate;
		}
	}

	// Error page handler
	void errorOut(int code, string msg, string debug_msg, Throwable ex)
	@safe {
		assert(!res.headerWritten);

		res.statusCode = code;
		if (settings && settings.errorPageHandler) {
			/*scope*/ auto err = new HTTPServerErrorInfo;
			err.code = code;
			err.message = msg;
			err.debugMessage = debug_msg;
			err.exception = ex;
			settings.errorPageHandler_(req, res, err);
		} else {
			if (debug_msg.length)
				res.writeBody(format("%s - %s\n\n%s\n\nInternal error information:\n%s", code, httpStatusText(code), msg, debug_msg));
			else res.writeBody(format("%s - %s\n\n%s", code, httpStatusText(code), msg));
		}
		assert(res.headerWritten);
	}

	bool parsed = false;
	/*bool*/ keep_alive = false;

	// parse the request
	try {
		logTrace("reading request..");

		// limit the total request time
		InputStreamProxy reqReader = http_stream;
		if (settings.maxRequestTime > dur!"seconds"(0) && settings.maxRequestTime != Duration.max) {
			timeout_http_input_stream = FreeListRef!TimeoutHTTPInputStream(reqReader, settings.maxRequestTime, reqtime);
			reqReader = timeout_http_input_stream;
		}

		// basic request parsing
		parseRequestHeader(req, reqReader, request_allocator, settings.maxRequestHeaderSize, settings.maxRequestHeaderLineSize);
		logTrace("Got request header.");

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

		foreach (ctx; listen_info.m_virtualHosts)
			if (icmp2(ctx.settings.hostName, reqhost) == 0 &&
				(!reqport || reqport == ctx.settings.port))
			{
				context = ctx;
				settings = ctx.settings;
				request_task = ctx.requestHandler;
				break;
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

		// limit request size
		if (auto pcl = "Content-Length" in req.headers) {
			string v = *pcl;
			auto contentLength = parse!ulong(v); // DMDBUG: to! thinks there is a H in the string
			enforceBadRequest(v.length == 0, "Invalid content-length");
			enforceBadRequest(settings.maxRequestSize <= 0 || contentLength <= settings.maxRequestSize, "Request size too big");
			limited_http_input_stream = FreeListRef!LimitedHTTPInputStream(reqReader, contentLength);
		} else if (auto pt = "Transfer-Encoding" in req.headers) {
			enforceBadRequest(icmp2(*pt, "chunked") == 0);
			chunked_input_stream = createChunkedInputStreamFL(reqReader);
			InputStreamProxy ciproxy = chunked_input_stream;
			limited_http_input_stream = FreeListRef!LimitedHTTPInputStream(ciproxy, settings.maxRequestSize, true);
		} else {
			limited_http_input_stream = FreeListRef!LimitedHTTPInputStream(reqReader, 0);
		}
		req.bodyReader = limited_http_input_stream;

		// handle Expect header
		if (auto pv = "Expect" in req.headers) {
			if (icmp2(*pv, "100-continue") == 0) {
				logTrace("sending 100 continue");
				http_stream.write("HTTP/1.1 100 Continue\r\n\r\n");
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
		res.headers["Date"] = formatRFC822DateAlloc(reqtime);
		if (req.persistent)
			res.headers["Keep-Alive"] = formatAlloc(
				request_allocator, "timeout=%d", settings.keepAliveTimeout.total!"seconds"());

		// finished parsing the request
		parsed = true;
		logTrace("persist: %s", req.persistent);
		keep_alive = req.persistent;

		if (context.settings.rejectConnectionPredicate !is null)
		{
			import std.socket : Address, parseAddress;

			auto forward = req.headers.get("X-Forwarded-For", null);
			if (forward !is null)
			{
				try {
					auto ix = forward.indexOf(',');
					if (ix != -1)
						forward = forward[0 .. ix];
					if (context.settings.rejectConnectionPredicate(NetworkAddress(parseAddress(forward))))
						errorOut(HTTPStatus.forbidden,
							httpStatusText(HTTPStatus.forbidden), null, null);
				} catch (Exception e)
					logTrace("Malformed X-Forwarded-For header: %s", e.msg);
			}
		}

		// handle the request
		logTrace("handle request (body %d)", req.bodyReader.leastSize);
		res.httpVersion = req.httpVersion;
		request_task(req, res);

		// if no one has written anything, return 404
		if (!res.headerWritten) {
			string dbg_msg;
			logDiagnostic("No response written for %s", req.requestURI);
			if (settings.options & HTTPServerOption.errorStackTraces)
				dbg_msg = format("No routes match path '%s'", req.requestURI);
			errorOut(HTTPStatus.notFound, httpStatusText(HTTPStatus.notFound), dbg_msg, null);
		}
	} catch (HTTPStatusException err) {
		if (!res.headerWritten) errorOut(err.status, err.msg, err.debugMessage, err);
		else logDiagnostic("HTTPStatusException while writing the response: %s", err.msg);
		debug logDebug("Exception while handling request %s %s: %s", req.method,
					   req.requestURI, () @trusted { return err.toString().sanitize; } ());
		if (!parsed || res.headerWritten || justifiesConnectionClose(err.status))
			keep_alive = false;
	} catch (UncaughtException e) {
		auto status = parsed ? HTTPStatus.internalServerError : HTTPStatus.badRequest;
		string dbg_msg;
		if (settings.options & HTTPServerOption.errorStackTraces)
			dbg_msg = () @trusted { return e.toString().sanitize; } ();
		if (!res.headerWritten && tcp_connection.connected)
			errorOut(status, httpStatusText(status), dbg_msg, e);
		else logDiagnostic("Error while writing the response: %s", e.msg);
		debug logDebug("Exception while handling request %s %s: %s", req.method,
					   req.requestURI, () @trusted { return e.toString().sanitize(); } ());
		if (!parsed || res.headerWritten || !cast(Exception)e) keep_alive = false;
	}

	if (tcp_connection.connected && keep_alive) {
		if (req.bodyReader && !req.bodyReader.empty) {
			req.bodyReader.pipe(nullSink);
			logTrace("dropped body");
		}
	}

	// finalize (e.g. for chunked encoding)
	res.finalize();

	if (res.m_requiresConnectionClose)
		keep_alive = false;

	// NOTE: req.m_files may or may not be parsed/filled with actual data, as
	//       it is lazily initialized when calling the .files or .form
	//       properties
	foreach (k, v ; req.m_files.byKeyValue) {
		if (existsFile(v.tempPath)) {
			removeFile(v.tempPath);
			logDebug("Deleted upload tempfile %s", v.tempPath.toString());
		}
	}

	if (!req.noLog) {
		// log the request to access log
		foreach (log; context.loggers)
			log.log(req, res);
	}

	//logTrace("return %s (used pool memory: %s/%s)", keep_alive, request_allocator.allocatedSize, request_allocator.totalSize);
	logTrace("return %s", keep_alive);
	return keep_alive != false;
}


private void parseRequestHeader(InputStream, Allocator)(HTTPServerRequest req, InputStream http_stream, Allocator alloc, ulong max_header_size, size_t max_header_line_size)
	if (isInputStream!InputStream)
{
	import std.string : indexOf;
	import vibe.stream.operations : readLine;

	auto stream = FreeListRef!LimitedHTTPInputStream(http_stream, max_header_size);

	logTrace("HTTP server reading status line");
	auto reqln = () @trusted { return cast(string)stream.readLine(max_header_line_size, "\r\n", alloc); }();

	logTrace("--------------------");
	logTrace("HTTP server request:");
	logTrace("--------------------");
	logTrace("%s", reqln);

	//Method
	auto pos = reqln.indexOf(' ');
	enforceBadRequest(pos >= 0, "invalid request method");

	req.method = httpMethodFromString(reqln[0 .. pos]);
	reqln = reqln[pos+1 .. $];
	//Path
	pos = reqln.indexOf(' ');
	enforceBadRequest(pos >= 0, "invalid request path");

	req.requestURI = reqln[0 .. pos];
	reqln = reqln[pos+1 .. $];

	req.httpVersion = parseHTTPVersion(reqln);

	//headers
	parseRFC5322Header(stream, req.headers, max_header_line_size, alloc, false);

	foreach (k, v; req.headers.byKeyValue)
		logTrace("%s: %s", k, v);
	logTrace("--------------------");
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

private string formatRFC822DateAlloc(SysTime time)
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

