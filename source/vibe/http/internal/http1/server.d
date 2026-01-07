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
import std.format : format, formattedWrite;


/** Treats an existing connection as an HTTP connection and processes incoming
	requests.

	After all requests have been processed, the connection will be closed and
	the function returns to the caller.

	Params:
		connection = The stream to treat as an incoming HTTP client connection.
		context = Information about the incoming listener and available
			virtual hosts
*/
void handleHTTP1Connection(TLSStreamType)(TCPConnection connection, TLSStreamType tls_stream, StreamProxy http_stream, HTTPServerContext context, ref NetworkAddress remote_address)
@safe {
	scope request_allocator = createRequestAllocator();
	scope (exit) () @trusted { freeRequestAllocator(request_allocator); }();
	while (!connection.empty) {
		HTTPServerSettings settings;
		bool keep_alive;

		static if (HaveNoTLS) {} else {
			// handle oderly TLS shutdowns
			if (tls_stream && tls_stream.empty) break;
		}

		() @trusted {
			handleRequest!TLSStreamType(http_stream, connection, context, settings, keep_alive, request_allocator, remote_address);
			request_allocator.deallocateAll();
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


private bool handleRequest(TLSStreamType, Allocator)(StreamProxy http_stream, TCPConnection tcp_connection, HTTPServerContext listen_info, ref HTTPServerSettings settings, ref bool keep_alive, scope Allocator request_allocator, ref NetworkAddress remote_address)
@safe {
	import vibe.container.internal.utilallocator : make, dispose;
	import vibe.http.internal.utils : formatRFC822DateAlloc;
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
	req.clientAddress = remote_address;

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
	auto exchange = () @trusted { return request_allocator.make!HTTP1ServerExchange(http_stream, cproxy); } ();
	scope (exit) () @trusted { request_allocator.dispose(exchange); } ();
	auto res = FreeListRef!HTTPServerResponse(exchange, settings, request_allocator/*.Scoped_payload*/);
	req.tls = res.m_tls = listen_info.tlsContext !is null;
	if (req.tls) {
		static if (HaveNoTLS) assert(false);
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
		uint h2 = parseRequestHeader(req, reqReader, request_allocator, settings.maxRequestHeaderSize, settings.maxRequestHeaderLineSize, !!(settings.options & HTTPServerOption.enableHTTP2));
		if (h2) {
			import vibe.http.internal.http2.server : handleHTTP2Connection;
			import vibe.http.internal.http2.settings : HTTP2ServerContext, HTTP2Settings;

			// start http/2 with prior knowledge
			uint len = 22 - h2;
			ubyte[] dummy; dummy.length = len;

			http_stream.read(dummy); // finish reading connection preface
			auto h2settings = HTTP2Settings();
			auto h2context = new HTTP2ServerContext(listen_info, h2settings, remote_address);
			handleHTTP2Connection(tcp_connection, tcp_connection, h2context, true);
			return true;
		}

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
		if (auto pt = "Transfer-Encoding" in req.headers) {
			enforceBadRequest(icmp2(*pt, "chunked") == 0);

			// see RFC 9112 6.3.3 and GitHub security advisonry GHSA-hm69-r6ch-92wx
			enforceBadRequest("Content-Length" !in req.headers);

			chunked_input_stream = createChunkedInputStreamFL(reqReader);
			InputStreamProxy ciproxy = chunked_input_stream;
			limited_http_input_stream = FreeListRef!LimitedHTTPInputStream(ciproxy, settings.maxRequestSize, true);
		} else if (auto pcl = "Content-Length" in req.headers) {
			string v = *pcl;
			auto contentLength = parse!ulong(v); // DMDBUG: to! thinks there is a H in the string
			enforceBadRequest(v.length == 0, "Invalid content-length");
			enforceBadRequest(settings.maxRequestSize <= 0 || contentLength <= settings.maxRequestSize, "Request size too big");
			limited_http_input_stream = FreeListRef!LimitedHTTPInputStream(reqReader, contentLength);
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
		if (req.method == HTTPMethod.HEAD) exchange.m_isHeadResponse = true;
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

	if (exchange.m_requiresConnectionClose)
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


private uint parseRequestHeader(InputStream, Allocator)(HTTPServerRequest req, InputStream http_stream, Allocator alloc, ulong max_header_size, size_t max_header_line_size, bool enable_http2)
	if (isInputStream!InputStream)
{
	import std.string : indexOf;
	import vibe.stream.operations : readLine;

	auto stream = FreeListRef!LimitedHTTPInputStream(http_stream, max_header_size);

	logTrace("HTTP server reading status line");
	auto reqln = () @trusted { return cast(string)stream.readLine(max_header_line_size, "\r\n", alloc); }();

	if(reqln == "PRI * HTTP/2.0" && enable_http2) return cast(uint)reqln.length;

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

	return 0;
}

class HTTP1ServerExchange : HTTPServerExchange {
	import vibe.stream.counting : CountingOutputStream, createCountingOutputStreamFL;
	import vibe.stream.wrapper : createConnectionProxyStream, createConnectionProxyStreamFL;
	import vibe.stream.zlib : ZlibOutputStream, createDeflateOutputStreamFL, createGzipOutputStreamFL;

	protected {
		StreamProxy m_conn;
		ConnectionStreamProxy m_rawConnection;
		bool m_isHeadResponse = false;
		OutputStreamProxy m_bodyWriter;
		FreeListRef!ChunkedOutputStream m_chunkedBodyWriter;
		FreeListRef!CountingOutputStream m_countingWriter;
		FreeListRef!ZlibOutputStream m_zlibOutputStream;
		bool m_headerWritten = false;
		bool m_requiresConnectionClose;
	}

	this(StreamProxy conn, ConnectionStreamProxy raw_connection)
	@safe {
		m_conn = conn;
		m_rawConnection = raw_connection;
		m_countingWriter = createCountingOutputStreamFL(conn);
	}

	override @property bool isHeadResponse() const { return m_isHeadResponse; }
	override @property bool headerWritten() const { return m_headerWritten; }
	override @property ulong bytesWritten() @safe const { return m_countingWriter.bytesWritten; }

	override void writeBody(HTTPServerResponse res, RandomAccessStreamProxy stream)
	{
		assert(!m_headerWritten, "A body was already written!");
		writeHeader(res);
		if (m_isHeadResponse) return;

		auto bytes = stream.size - stream.tell();
		stream.pipe(m_conn);
		m_countingWriter.increment(bytes);
	}

	override void writeBody(HTTPServerResponse res, InputStreamProxy stream, ulong num_bytes = ulong.max)
	{
		assert(!m_headerWritten, "A body was already written!");
		writeHeader(res);
		if (m_isHeadResponse) return;

		if (num_bytes != ulong.max) {
			stream.pipe(m_conn, num_bytes);
			m_countingWriter.increment(num_bytes);
		} else stream.pipe(m_countingWriter);
	}

	override void writeVoidBody(HTTPServerResponse res)
	{
		if (!isHeadResponse) {
			assert("Content-Length" !in res.headers);
			assert("Transfer-Encoding" !in res.headers);
		}
		assert(!m_headerWritten);
		writeHeader(res);
		m_conn.flush();
	}

	override OutputStreamProxy bodyWriter(HTTPServerResponse res)
	{
		import std.conv : to;

		assert(!!m_conn);
		if (m_bodyWriter) {
			// for test responses, the body writer is pre-set, without headers
			// being written, so we may need to do that here
			if (!m_headerWritten) writeHeader(res);

			return m_bodyWriter;
		}

		assert(!m_headerWritten, "A void body was already written!");
		assert(res.statusCode >= 200, "1xx responses can't have body");

		if (m_isHeadResponse) {
			// for HEAD requests, we define a NullOutputWriter for convenience
			// - no body will be written. However, the request handler should call writeVoidBody()
			// and skip writing of the body in this case.
			if ("Content-Length" !in res.headers)
				res.headers["Transfer-Encoding"] = "chunked";
			writeHeader(res);
			m_bodyWriter = nullSink;
			return m_bodyWriter;
		}

		if ("Content-Encoding" in res.headers && "Content-Length" in res.headers) {
			// we do not known how large the compressed body will be in advance
			// so remove the content-length and use chunked transfer
			res.headers.remove("Content-Length");
		}

		if (auto pcl = "Content-Length" in res.headers) {
			writeHeader(res);
			m_countingWriter.writeLimit = (*pcl).to!ulong;
			m_bodyWriter = m_countingWriter;
		} else if (res.httpVersion <= HTTPVersion.HTTP_1_0) {
			if ("Connection" in res.headers)
				res.headers.remove("Connection"); // default to "close"
			writeHeader(res);
			m_bodyWriter = m_conn;
		} else {
			res.headers["Transfer-Encoding"] = "chunked";
			writeHeader(res);
			m_chunkedBodyWriter = createChunkedOutputStreamFL(m_countingWriter);
			m_bodyWriter = m_chunkedBodyWriter;
		}

		if (auto pce = "Content-Encoding" in res.headers) {
			if (icmp2(*pce, "gzip") == 0) {
				m_zlibOutputStream = createGzipOutputStreamFL(m_bodyWriter);
				m_bodyWriter = m_zlibOutputStream;
			} else if (icmp2(*pce, "deflate") == 0) {
				m_zlibOutputStream = createDeflateOutputStreamFL(m_bodyWriter);
				m_bodyWriter = m_zlibOutputStream;
			} else {
				logWarn("Unsupported Content-Encoding set in response: '"~*pce~"'");
			}
		}

		return m_bodyWriter;
	}

	override ConnectionStream switchProtocol(HTTPServerResponse res, string protocol)
	{
		res.statusCode = HTTPStatus.switchingProtocols;
		if (protocol.length) res.headers["Upgrade"] = protocol;
		writeVoidBody(res);
		m_requiresConnectionClose = true;
		m_headerWritten = true;
		return createConnectionProxyStream(m_conn, m_rawConnection);
	}

	override void switchProtocol(HTTPServerResponse res, string protocol, scope void delegate(scope ConnectionStream) @safe del)
	{
		res.statusCode = HTTPStatus.switchingProtocols;
		if (protocol.length) res.headers["Upgrade"] = protocol;
		writeVoidBody(res);
		m_requiresConnectionClose = true;
		m_headerWritten = true;
		() @trusted {
			auto conn = createConnectionProxyStreamFL(m_conn, m_rawConnection);
			del(conn);
		} ();
		finalize(res);
	}

	override ConnectionStream connectProxy(HTTPServerResponse res)
	{
		return createConnectionProxyStream(m_conn, m_rawConnection);
	}

	override void connectProxy(HTTPServerResponse res, scope void delegate(scope ConnectionStream) @safe del)
	{
		() @trusted {
			auto conn = createConnectionProxyStreamFL(m_conn, m_rawConnection);
			del(conn);
		} ();
		finalize(res);
	}

	void finalize(HTTPServerResponse res)
	{
		import std.conv : to;

		if (m_zlibOutputStream) {
			m_zlibOutputStream.finalize();
			m_zlibOutputStream.destroy();
		}
		if (m_chunkedBodyWriter) {
			m_chunkedBodyWriter.finalize();
			m_chunkedBodyWriter.destroy();
		}

		// ignore exceptions caused by an already closed connection - the client
		// may have closed the connection already and this doesn't usually indicate
		// a problem.
		if (m_rawConnection && m_rawConnection.connected) {
			try if (m_conn) m_conn.flush();
			catch (Exception e) logDebug("Failed to flush connection after finishing HTTP response: %s", e.msg);
			if (!isHeadResponse && m_countingWriter.bytesWritten < res.headers.get("Content-Length", "0").to!ulong) {
				logDebug("HTTP response only written partially before finalization. Terminating connection.");
				m_requiresConnectionClose = true;
			}

			m_rawConnection = ConnectionStreamProxy.init;
		}

		if (m_conn) {
			m_conn = StreamProxy.init;
			res.m_timeFinalized = Clock.currTime(UTC());
		}
	}

	private void writeHeader(HTTPServerResponse res)
	@safe {
		import vibe.stream.wrapper;

		assert(!m_headerWritten, "Try to write header after body has already begun.");
		assert(res.httpVersion != HTTPVersion.HTTP_1_0 || res.statusCode >= 200, "Informational status codes aren't supported by HTTP/1.0.");

		// Don't set m_headerWritten for 1xx status codes
		if (res.statusCode >= 200) m_headerWritten = true;
		auto dst = streamOutputRange!1024(m_conn);

		void writeLine(T...)(string fmt, T args)
		@safe {
			formattedWrite(() @trusted { return &dst; } (), fmt, args);
			dst.put("\r\n");
			logTrace(fmt, args);
		}

		logTrace("---------------------");
		logTrace("HTTP server response:");
		logTrace("---------------------");

		// write the status line
		writeLine("%s %d %s",
			getHTTPVersionString(res.httpVersion),
			res.statusCode,
			res.statusPhrase.length ? res.statusPhrase : httpStatusText(res.statusCode));

		// write all normal headers
		foreach (k, v; res.headers.byKeyValue) {
			dst.put(k);
			dst.put(": ");
			dst.put(v);
			dst.put("\r\n");
			logTrace("%s: %s", k, v);
		}

		logTrace("---------------------");

		// write cookies
		foreach (n, cookie; () @trusted { return res.cookies.byKeyValue; } ()) {
			dst.put("Set-Cookie: ");
			cookie.writeString(() @trusted { return &dst; } (), n);
			dst.put("\r\n");
		}

		// finalize response header
		dst.put("\r\n");
	}

	bool waitForConnectionClose(Duration timeout)
	{
		if (!m_rawConnection || !m_rawConnection.connected) return true;
		m_rawConnection.waitForData(timeout);
		return !m_rawConnection.connected;
	}

	@property bool connected()
	const {
		if (!m_rawConnection) return false;
		return m_rawConnection.connected;
	}
}

