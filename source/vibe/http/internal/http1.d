module vibe.http.internal.http1;

import vibe.core.stream;
import vibe.core.core : runTask;
import vibe.core.net;
import vibe.http.server;
import vibe.internal.allocator;
import vibe.internal.freelistref;
import vibe.internal.interfaceproxy : InterfaceProxy;
import vibe.core.file;
import vibe.core.log;
import vibe.inet.url;
import vibe.inet.webform;
import vibe.data.json;
import vibe.stream.wrapper : ConnectionProxyStream, createConnectionProxyStream, createConnectionProxyStreamFL;
import vibe.utils.array;
import vibe.utils.string;
import vibe.stream.counting;
import vibe.stream.operations;
import vibe.stream.zlib;
import vibe.textfilter.urlencode : urlEncode, urlDecode;
import vibe.stream.tls;

import std.datetime;
import std.typecons;
import std.conv;
import std.array;
import std.algorithm;
import std.format;
import std.parallelism;
import std.exception;
import std.string;
import std.encoding : sanitize;
import std.traits : isInstanceOf, ReturnType;

private alias TLSStreamType = ReturnType!(createTLSStreamFL!(InterfaceProxy!Stream)); 

void handleHTTP1Connection(ConnectionStream)(ConnectionStream connection, HTTPServerContext context)
@safe	if (isConnectionStream!ConnectionStream)
{
	connection.tcpNoDelay = true;

	logInfo("Connection");
    version(HaveNoTLS) {} else {
        TLSStreamType tls_stream;
    }

	// If this is a HTTPS server, initiate TLS
    if (context.tlsContext) {
        version (HaveNoTLS) assert(false, "No TLS support compiled in.");
        else {
            logDebug("Accept TLS connection: %s", context.tlsContext.kind);

            //TODO: determine if there's a better alternative to InterfaceProxy
            InterfaceProxy!Stream http_stream;
            http_stream = connection;

            // TODO: reverse DNS lookup for peer_name of the incoming connection for TLS client certificate verification purposes
            tls_stream = createTLSStreamFL(http_stream, context.tlsContext, TLSStreamState.accepting, null, connection.remoteAddress);
            http_stream = tls_stream;
        }
    }
	handleHTTP1Request(connection, context);
}

private void handleHTTP1Request(ConnectionStream)(ConnectionStream connection, HTTPContext context)
@safe
{
	logInfo("Request");

	HTTPServerSettings settings;
	InterfaceProxy!Stream http_stream;
	http_stream = connection;
	bool keep_alive;
	() @trusted {
		import vibe.internal.utilallocator: RegionListAllocator;
		version (VibeManualMemoryManagement)
			scope request_allocator = new RegionListAllocator!(shared(Mallocator), false)(1024, Mallocator.instance);
		else
			scope request_allocator = new RegionListAllocator!(shared(GCAllocator), true)(1024, GCAllocator.instance);

		originalHandleRequest(http_stream, connection, context, settings, keep_alive, request_allocator);

		if (!keep_alive) { connection.close; return; }
	} ();

	// NOTE: this requires that connection has no scoped destruction
	// Currently vibe-d/vibe-core mantains the destructor,
	// which prevents the closure from being built
	connection.waitForDataAsync( (bool st) @safe {
			if (!st) connection.close;
			else runTask(&handleHTTP1Request, connection, context);
		});
}

/* Previous vibe.http handleRequest
 * Gets called by handleHTTP1Request
 */
bool originalHandleRequest(InterfaceProxy!Stream http_stream, TCPConnection tcp_connection, HTTPServerContext listen_info, ref HTTPServerSettings settings, ref bool keep_alive, scope IAllocator request_allocator)
@safe {

	logInfo ("Old request handler");
	import std.algorithm.searching : canFind;

	SysTime reqtime = Clock.currTime(UTC());

	// some instances that live only while the request is running
	//FreeListRef!HTTPServerRequest req = FreeListRef!HTTPServerRequest(reqtime, listen_info.bindPort);
    auto req = HTTPServerRequest(reqtime, listen_info.bindPort);

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
	HTTPServerContext.VirtualHost context = listen_info.virtualHosts[0];
	HTTPServerRequestDelegate request_task = context.requestHandler;
	settings = context.settings;

	// temporarily set to the default settings, the virtual host specific settings will be set further down
	req.m_settings = settings;

	// Create the response object
	InterfaceProxy!ConnectionStream cproxy = tcp_connection;
	auto res = HTTPServerResponse(http_stream, cproxy, settings, request_allocator/*.Scoped_payload*/);
    auto istls = listen_info.tlsContext !is null;
    req.tls = istls;
    res.tls = istls;

 	if (req.tls) {
		version (HaveNoTLS) assert(false);
		else {
			static if (is(InterfaceProxy!ConnectionStream == ConnectionStream))
				req.clientCertificate = (cast(TLSStream)http_stream).peerCertificate;
			else
                req.clientCertificate = http_stream.extract!TLSStreamType.peerCertificate;
				assert(false);
		}
	}

	// Error page handler
	void errorOut(int code, string msg, string debug_msg, Throwable ex)
	@safe {
		assert(!res.headerWritten);

		// stack traces sometimes contain random bytes - make sure they are replaced
		debug_msg = sanitizeUTF8(cast(const(ubyte)[])debug_msg);

		res.setStatusCode(code);
		if (settings && settings.errorPageHandler) {
			/*scope*/ auto err = new HTTPServerErrorInfo;
			err.code = code;
			err.message = msg;
			err.debugMessage = debug_msg;
			err.exception = ex;
			settings.handleErrorPage(req, res, err);
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
		InterfaceProxy!InputStream reqReader = http_stream;
		if (settings.maxRequestTime > dur!"seconds"(0) && settings.maxRequestTime != Duration.max) {
			timeout_http_input_stream = FreeListRef!TimeoutHTTPInputStream(reqReader, settings.maxRequestTime, reqtime);
			reqReader = timeout_http_input_stream;
		}

		// basic request parsing
		parseRequestHeader(req, reqReader, request_allocator, settings.maxRequestHeaderSize);
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

		foreach (ctx; listen_info.virtualHosts)
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
			enforceBadRequest(icmp(*pt, "chunked") == 0);
			chunked_input_stream = createChunkedInputStreamFL(reqReader);
			InterfaceProxy!InputStream ciproxy = chunked_input_stream;
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
		res.headers["Date"] = formatRFC822DateAlloc(request_allocator, reqtime);
		if (req.persistent) res.headers["Keep-Alive"] = formatAlloc(request_allocator, "timeout=%d", settings.keepAliveTimeout.total!"seconds"());

		// finished parsing the request
		parsed = true;
		logTrace("persist: %s", req.persistent);
		keep_alive = req.persistent;

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
		else logDiagnostic("HTTPSterrorOutatusException while writing the response: %s", err.msg);
		debug logDebug("Exception while handling request %s %s: %s", req.method, req.requestURI, () @trusted { return err.toString().sanitize; } ());
		if (!parsed || res.headerWritten || justifiesConnectionClose(err.status))
			keep_alive = false;
	} catch (UncaughtException e) {
		auto status = parsed ? HTTPStatus.internalServerError : HTTPStatus.badRequest;
		string dbg_msg;
		if (settings.options & HTTPServerOption.errorStackTraces) dbg_msg = () @trusted { return e.toString().sanitize; } ();
		if (!res.headerWritten && tcp_connection.connected) errorOut(status, httpStatusText(status), dbg_msg, e);
		else logDiagnostic("Error while writing the response: %s", e.msg);
		debug logDebug("Exception while handling request %s %s: %s", req.method, req.requestURI, () @trusted { return e.toString().sanitize(); } ());
		if (!parsed || res.headerWritten || !cast(Exception)e) keep_alive = false;
	}

	if (tcp_connection.connected) {
		if (req.bodyReader && !req.bodyReader.empty) {
			req.bodyReader.pipe(nullSink);
			logTrace("dropped body");
		}
	}

	// finalize (e.g. for chunked encoding)
	res.finalize();

	foreach (k, v ; req._files) {
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

final class LimitedHTTPInputStream : LimitedInputStream {
@safe:

	this(InterfaceProxy!InputStream stream, ulong byte_limit, bool silent_limit = false) {
		super(stream, byte_limit, silent_limit, true);
	}
	override void onSizeLimitReached() {
		throw new HTTPStatusException(HTTPStatus.requestEntityTooLarge);
	}
}

final class TimeoutHTTPInputStream : InputStream {
@safe:

	private {
		long m_timeref;
		long m_timeleft;
		InterfaceProxy!InputStream m_in;
	}

	this(InterfaceProxy!InputStream stream, Duration timeleft, SysTime reftime)
	{
		enforce(timeleft > 0.seconds, "Timeout required");
		m_in = stream;
		m_timeleft = timeleft.total!"hnsecs"();
		m_timeref = reftime.stdTime();
	}

	@property bool empty() { enforce(m_in, "InputStream missing"); return m_in.empty(); }
	@property ulong leastSize() { enforce(m_in, "InputStream missing"); return m_in.leastSize();  }
	@property bool dataAvailableForRead() {  enforce(m_in, "InputStream missing"); return m_in.dataAvailableForRead; }
	const(ubyte)[] peek() { return m_in.peek(); }

	size_t read(scope ubyte[] dst, IOMode mode)
	{
		enforce(m_in, "InputStream missing");
		size_t nread = 0;
		checkTimeout();
		// FIXME: this should use ConnectionStream.waitForData to enforce the timeout during the
		// read operation
		return m_in.read(dst, mode);
	}

	alias read = InputStream.read;

	private void checkTimeout()
	@safe {
		auto curr = Clock.currStdTime();
		auto diff = curr - m_timeref;
		if (diff > m_timeleft) throw new HTTPStatusException(HTTPStatus.RequestTimeout);
		m_timeleft -= diff;
		m_timeref = curr;
	}
}

