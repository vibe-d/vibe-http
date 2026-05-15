/**
	HTTP (reverse) proxy implementation

	Copyright: © 2012 Sönke Ludwig
	License: Subject to the terms of the MIT license, as written in the included LICENSE.txt file.
	Authors: Sönke Ludwig
*/
module vibe.http.proxy;

import vibe.core.log;
import vibe.http.client;
import vibe.http.server;
import vibe.inet.message;
import vibe.stream.operations;
import vibe.internal.interfaceproxy : InterfaceProxy;

import std.conv;
import std.exception;


/*
	Bidirectional tunnel between two stream-like endpoints (CONNECT body or
	protocol upgrade such as WebSocket).

	Two fibers, one per direction.  Each waits for data with a timeout and
	checks a shared `done` flag.  Uses `waitForDataEx` to distinguish
	timeout from EOF.
*/
private void tunnelBidirectional(A, B)(A a, B b) @safe
{
	import vibe.core.core : runTask;

	logInfo("tunnelBidirectional started");

	auto finished = new bool;

	static void pumpAToB(A src, B dst, bool *finished) nothrow {
		try pump(src, dst, finished);
		catch (Exception e) {
			logDebug("Proxy tunnel: forward ended: %s", e.msg);
		}
		*finished = true;
	}

	auto t = runTask(&pumpAToB, a, b, finished);

	try pump(b, a, finished);
	catch (Exception e) logDebug("Proxy tunnel: forward ended: %s", e.msg);

	*finished = true;
	try t.join();
	catch (Exception e) logDebug("Proxy tunnel: join failed: %s", e.msg);

	logInfo("tunnelBidirectional finished");
}

/*
	Single-direction pump.  Waits for data with a timeout so it can
	periodically observe the shared `done` flag.  Uses `waitForDataEx`
	to distinguish timeout from EOF.
*/
private void pump(Src, Dst)(Src src, Dst dst, bool *finished)
{
	import core.time : seconds;
	import std.algorithm : min;
	import vibe.stream.wrapper : ConnectionProxyStream;

	enum checkInterval = 1.seconds;
	auto buf = new ubyte[64*1024];

	while (!*finished)
	{
		WaitForDataStatus status;

		static if (__traits(hasMember, Src, "waitForDataEx"))
			status = src.waitForDataEx(checkInterval);
		else static if (is(Src : ConnectionStream))
		{
			auto cps = cast(ConnectionProxyStream)src;
			assert(cps, "Tunnel requires a ConnectionProxyStream");
			status = cps.waitForDataEx(checkInterval);
		}
		else
			static assert(false, "Tunnel source must support waitForDataEx");

		final switch (status)
		{
		case WaitForDataStatus.dataAvailable:
			auto chunk = min(src.leastSize, buf.length);
			if (chunk == 0) return;
			src.read(buf[0 .. chunk]);
			dst.write(buf[0 .. chunk]);
			break;
		case WaitForDataStatus.noMoreData:
			*finished = true;
			return;
		case WaitForDataStatus.timeout:
			break;
		}
	}
}


/*
	TODO:
		- use a client pool
		- implement a path based reverse proxy
*/

/**
	Transparently forwards all requests to the proxy to another host.

	The configurations set in 'settings' and 'proxy_settings' determines the exact
	behavior.
*/
void listenHTTPProxy(HTTPServerSettings settings, HTTPProxySettings proxy_settings)
{
	// disable all advanced parsing in the server
	settings.options = HTTPServerOption.none;
	listenHTTP(settings, proxyRequest(proxy_settings));
}

/**
	Transparently forwards all requests to the proxy to a destination_host.

	You can use the hostName field in the 'settings' to combine multiple internal HTTP servers
	into one public web server with multiple virtual hosts.
*/
void listenHTTPReverseProxy(HTTPServerSettings settings, string destination_host, ushort destination_port)
{
	URL url;
	url.schema = "http";
	url.host = destination_host;
	url.port = destination_port;
	auto proxy_settings = new HTTPProxySettings(ProxyMode.reverse);
	proxy_settings.destination = url;
	listenHTTPProxy(settings, proxy_settings);
}

/**
	Transparently forwards all requests to the proxy to the requestURL of the request.
*/
void listenHTTPForwardProxy(HTTPServerSettings settings) {
	auto proxy_settings = new HTTPProxySettings(ProxyMode.forward);
	proxy_settings.handleConnectRequests = true;
	listenHTTPProxy(settings, proxy_settings);
}

/**
	Returns a HTTP request handler that forwards any request to the specified or requested host/port.
*/
HTTPServerRequestDelegateS proxyRequest(HTTPProxySettings settings)
{
	static immutable string[] non_forward_headers = ["Content-Length", "Transfer-Encoding", "Content-Encoding", "Connection"];
	static InetHeaderMap non_forward_headers_map;
	if (non_forward_headers_map.length == 0)
		foreach (n; non_forward_headers)
			non_forward_headers_map[n] = "";

	void handleRequest(scope HTTPServerRequest req, scope HTTPServerResponse res)
	@safe {
		auto url = settings.destination;

		if (settings.proxyMode == ProxyMode.reverse) {
			url.localURI = req.requestURL;
		}
		else {
			url = URL(req.requestURL);
		}

		//handle connect tunnels
		if (req.method == HTTPMethod.CONNECT) {
			if (!settings.handleConnectRequests)
			{
				throw new HTTPStatusException(HTTPStatus.methodNotAllowed);
			}

			// CONNECT resources are of the form server:port and not
			// schema://server:port, so they need some adjustment
			// TODO: use a more efficient means to parse this
			url = URL.parse("http://"~req.requestURL);

			TCPConnection ccon;
			try ccon = connectTCP(url.getFilteredHost, url.port);
			catch (Exception e) {
				throw new HTTPStatusException(HTTPStatus.badGateway, "Connection to upstream server failed: "~e.msg);
			}

			res.writeVoidBody();
			auto scon = res.connectProxy();
			tunnelBidirectional(scon, ccon);
			return;
		}

		//handle protocol upgrades
		auto pUpgrade = "Upgrade" in req.headers;
		auto pConnection = "Connection" in req.headers;


		import std.algorithm : splitter, canFind;
		import vibe.internal.string : icmp2;
		import std.string : strip;
		bool isUpgrade = pConnection && (*pConnection).splitter(',').canFind!(a => a.strip.icmp2("upgrade") == 0);

		void setupClientRequest(scope HTTPClientRequest creq)
		{
			creq.method = req.method;
			creq.headers = req.headers.dup;
			creq.headers["Host"] = url.getFilteredHost;

			//handle protocol upgrades
			if (!isUpgrade) {
				creq.headers["Connection"] = "keep-alive";
			}
			if (settings.avoidCompressedRequests && "Accept-Encoding" in creq.headers)
				creq.headers.remove("Accept-Encoding");
			if (auto pfh = "X-Forwarded-Host" !in creq.headers) creq.headers["X-Forwarded-Host"] = req.headers["Host"];
			if (auto pfp = "X-Forwarded-Proto" !in creq.headers) creq.headers["X-Forwarded-Proto"] = req.tls ? "https" : "http";
			if (auto pff = "X-Forwarded-For" in req.headers) creq.headers["X-Forwarded-For"] = *pff ~ ", " ~ req.peer;
			else creq.headers["X-Forwarded-For"] = req.peer;
			req.bodyReader.pipe(creq.bodyWriter);
		}

		void handleClientResponse(scope HTTPClientResponse cres)
		{
			// copy the response to the original requester
			res.statusCode = cres.statusCode;

			//handle protocol upgrades
			if (cres.statusCode == HTTPStatus.switchingProtocols && isUpgrade) {
				res.headers = cres.headers.dup;

				auto scon = res.switchProtocol("");
				auto ccon = cres.switchProtocol("");

				tunnelBidirectional(ccon, scon);
				return;
			}

			// special case for empty response bodies
			if ("Content-Length" !in cres.headers && "Transfer-Encoding" !in cres.headers || req.method == HTTPMethod.HEAD) {
				foreach (key, ref value; cres.headers.byKeyValue)
					if (icmp2(key, "Connection") != 0)
						res.headers.addField(key,value);
				res.writeVoidBody();
				return;
			}

			// enforce compatibility with HTTP/1.0 clients that do not support chunked encoding
			// (Squid and some other proxies)
			if (res.httpVersion == HTTPVersion.HTTP_1_0 && ("Transfer-Encoding" in cres.headers || "Content-Length" !in cres.headers)) {
				// copy all headers that may pass from upstream to client
				foreach (n, ref v; cres.headers.byKeyValue)
					if (n !in non_forward_headers_map)
						res.headers.addField(n,v);

				if ("Transfer-Encoding" in res.headers) res.headers.remove("Transfer-Encoding");
				auto content = cres.bodyReader.readAll(1024*1024);
				res.headers["Content-Length"] = to!string(content.length);
				if (res.isHeadResponse) res.writeVoidBody();
				else res.bodyWriter.write(content);
				return;
			}

			// to perform a verbatim copy of the client response
			if ("Content-Length" in cres.headers) {
				if ("Content-Encoding" in res.headers) res.headers.remove("Content-Encoding");
				foreach (key, ref value; cres.headers.byKeyValue)
					if (icmp2(key, "Connection") != 0)
						res.headers.addField(key,value);
				auto size = cres.headers["Content-Length"].to!size_t();
				if (res.isHeadResponse) res.writeVoidBody();
				else cres.readRawBody((scope InterfaceProxy!InputStream reader) { res.writeRawBody(reader, size); });
				assert(res.headerWritten);
				return;
			}

			// fall back to a generic re-encoding of the response
			// copy all headers that may pass from upstream to client
			foreach (n, ref v; cres.headers.byKeyValue)
				if (n !in non_forward_headers_map)
					res.headers.addField(n,v);
			if (res.isHeadResponse) res.writeVoidBody();
			else cres.bodyReader.pipe(res.bodyWriter);
		}

		try requestHTTP(url, &setupClientRequest, &handleClientResponse);
		catch (Exception e) {
			throw new HTTPStatusException(HTTPStatus.badGateway, "Connection to upstream server failed: "~e.msg);
		}
	}

	return &handleRequest;
}

/**
	Returns a HTTP request handler that forwards any request to the specified host/port.
*/
HTTPServerRequestDelegateS reverseProxyRequest(string destination_host, ushort destination_port)
{
	URL url;
	url.schema = "http";
	url.host = destination_host;
	url.port = destination_port;
	auto settings = new HTTPProxySettings(ProxyMode.reverse);
	settings.destination = url;
	return proxyRequest(settings);
}

/// ditto
HTTPServerRequestDelegateS reverseProxyRequest(URL destination)
{
	auto settings = new HTTPProxySettings(ProxyMode.reverse);
	settings.destination = destination;
	return proxyRequest(settings);
}

/**
	Returns a HTTP request handler that forwards any request to the requested host/port.
*/
HTTPServerRequestDelegateS forwardProxyRequest() {
    return proxyRequest(new HTTPProxySettings(ProxyMode.forward));
}

/**
	Enum to represent the two modes a proxy can operate as.
*/
enum ProxyMode {forward, reverse}

/**
	Provides advanced configuration facilities for reverse proxy servers.
*/
final class HTTPProxySettings {
	/// Scheduled for deprecation - use `destination.host` instead.
	@property string destinationHost() const { return destination.host; }
	/// ditto
	@property void destinationHost(string host) { destination.host = host; }
	/// Scheduled for deprecation - use `destination.port` instead.
	@property ushort destinationPort() const { return destination.port; }
	/// ditto
	@property void destinationPort(ushort port) { destination.port = port; }

	/// The destination URL to forward requests to
	URL destination = URL("http", InetPath(""));
	/// The mode of the proxy i.e forward, reverse
	ProxyMode proxyMode;
	/// Avoids compressed transfers between proxy and destination hosts
	bool avoidCompressedRequests;
	/// Handle CONNECT requests for creating a tunnel to the destination host
	bool handleConnectRequests;

	/// Empty default constructor for backwards compatibility - will be deprecated soon.
	deprecated("Pass an explicit `ProxyMode` argument")
	this() { proxyMode = ProxyMode.reverse; }
	/// Explicitly sets the proxy mode.
	this(ProxyMode mode) { proxyMode = mode; }
}
/// Compatibility alias
deprecated("Use `HTTPProxySettings(ProxyMode.reverse)` instead.")
alias HTTPReverseProxySettings = HTTPProxySettings;
