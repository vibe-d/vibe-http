module vibe.http.internal.http1.client;

import vibe.container.internal.utilallocator;
import vibe.core.connectionpool;
import vibe.core.log;
import vibe.http.client;
import vibe.internal.freelistref;
import vibe.stream.counting;
import vibe.stream.operations;
import vibe.stream.wrapper : createConnectionProxyStream;
import vibe.stream.zlib;

import core.time : Duration, seconds;
import std.exception : enforce;
import std.conv : parse, to;
import std.datetime : Clock, UTC, SysTime;
import std.string : icmp, strip;


class HTTP1ClientExchange : HTTPClientExchange {
	private {
		LockedConnection!HTTPClient m_lockedConnection;
		HTTPClient m_client;
		FreeListRef!LimitedInputStream m_limitedInputStream;
		FreeListRef!ChunkedInputStream m_chunkedInputStream;
		FreeListRef!ZlibInputStream m_zlibInputStream;
		FreeListRef!EndCallbackInputStream m_endCallback;
		InputStreamProxy m_bodyReader;
		bool m_closeConn;
		int m_maxRequests;
	}
@safe:

	this(HTTPClient client, bool close_conn)
	{
		m_closeConn = close_conn;
	}

	@property int maxRequests() const { return m_maxRequests; }

	@property bool closeConnection() const nothrow { return m_closeConn; }

	@property bool done() const nothrow { return !m_client; }

	@property ref LockedConnection!HTTPClient lockedConnection() { return m_lockedConnection; }

	InputStreamProxy bodyReader(HTTPClientResponse res)
	{
		if( m_bodyReader ) return m_bodyReader;

		assert (m_client, "Response was already read or no response body, may not use bodyReader.");

		// prepare body the reader
		if (auto pte = "Transfer-Encoding" in res.headers) {
			enforce(*pte == "chunked");
			m_chunkedInputStream = createChunkedInputStreamFL(m_client.m_stream);
			m_bodyReader = this.m_chunkedInputStream;
		} else if (auto pcl = "Content-Length" in res.headers) {
			m_limitedInputStream = createLimitedInputStreamFL(m_client.m_stream, to!ulong(*pcl));
			m_bodyReader = m_limitedInputStream;
		} else if (isKeepAliveResponse(res)) {
			m_limitedInputStream = createLimitedInputStreamFL(m_client.m_stream, 0);
			m_bodyReader = m_limitedInputStream;
		} else {
			m_bodyReader = m_client.m_stream;
		}

		if( auto pce = "Content-Encoding" in res.headers ){
			if( *pce == "deflate" ){
				m_zlibInputStream = createDeflateInputStreamFL(m_bodyReader);
				m_bodyReader = m_zlibInputStream;
			} else if( *pce == "gzip" || *pce == "x-gzip"){
				m_zlibInputStream = createGzipInputStreamFL(m_bodyReader);
				m_bodyReader = m_zlibInputStream;
			}
			else enforce(*pce == "identity" || *pce == "", "Unsuported content encoding: "~*pce);
		}

		// be sure to free resouces as soon as the response has been read
		m_endCallback = createEndCallbackInputStreamFL(m_bodyReader, &this.finalize);
		m_bodyReader = m_endCallback;

		return m_bodyReader;
	}

	void finalize()
	{
		finalize(m_closeConn);
	}
	void finalize(bool disconnect)
	{
		// ignore duplicate and too early calls to finalize
		// (too early happesn for empty response bodies)
		if (!m_client) return;

		auto cli = m_client;
		m_client = null;
		cli.m_responding = false;
		destroy(m_endCallback);
		destroy(m_zlibInputStream);
		destroy(m_chunkedInputStream);
		destroy(m_limitedInputStream);
		if (disconnect) cli.disconnect();
		destroy(m_lockedConnection);
	}

	void readResponse(HTTPClientResponse res, bool has_body, typeof(createRequestAllocator()) alloc, SysTime connected_time)
	{
		doReadResponse(res, has_body, alloc, connected_time);
	}

	void readResponse(HTTPClientResponse res, bool has_body, IAllocator alloc, SysTime connected_time)
	{
		doReadResponse(res, has_body, alloc, connected_time);
	}

	private void doReadResponse(Allocator)(HTTPClientResponse res, bool has_body, Allocator alloc, SysTime connected_time)
	{
		import vibe.inet.message : parseRFC5322Header;
		import std.algorithm.iteration : splitter;
		import std.algorithm.searching : startsWith;

		scope(failure) finalize(true);

		// read and parse status line ("HTTP/#.# #[ $]\r\n")
		logTrace("HTTP client reading status line");
		string stln = () @trusted { return cast(string)m_client.m_stream.readLine(HTTPClient.maxHeaderLineLength, "\r\n", alloc); } ();
		logTrace("stln: %s", stln);
		res.httpVersion = parseHTTPVersion(stln);

		enforce(stln.startsWith(" "));
		stln = stln[1 .. $];
		res.statusCode = parse!int(stln);
		if( stln.length > 0 ){
			enforce(stln.startsWith(" "));
			stln = stln[1 .. $];
			res.statusPhrase = stln;
		}

		// read headers until an empty line is hit
		parseRFC5322Header(m_client.m_stream, res.headers, HTTPClient.maxHeaderLineLength, alloc, false);

		logTrace("---------------------");
		logTrace("HTTP client response:");
		logTrace("---------------------");
		logTrace("%s", res);
		foreach (k, v; res.headers.byKeyValue)
			logTrace("%s: %s", k, v);
		logTrace("---------------------");
		Duration server_timeout;
		bool has_server_timeout;
		if (auto pka = "Keep-Alive" in res.headers) {
			foreach(s; splitter(*pka, ',')){
				auto pair = s.splitter('=');
				auto name = pair.front.strip();
				pair.popFront();
				if (icmp(name, "timeout") == 0) {
					has_server_timeout = true;
					server_timeout = pair.front.to!int().seconds;
				} else if (icmp(name, "max") == 0) {
					m_maxRequests = pair.front.to!int();
				}
			}
		}
		Duration elapsed = Clock.currTime(UTC()) - connected_time;
		if (res.headers.get("Connection") == "close") {
			// this header will trigger m_client.disconnect() in m_client.doRequest() when it goes out of scope
		} else if (has_server_timeout && m_client.m_keepAliveTimeout > server_timeout) {
			m_client.m_keepAliveLimit = Clock.currTime(UTC()) + server_timeout - elapsed;
		} else if (res.httpVersion == HTTPVersion.HTTP_1_1) {
			m_client.m_keepAliveLimit = Clock.currTime(UTC()) + m_client.m_keepAliveTimeout;
		}

		if (!has_body) finalize();
	}

	void readRawBody(scope void delegate(scope InputStreamProxy stream) @safe del)
	{
		assert(!m_bodyReader, "May not mix use of readRawBody and bodyReader.");
		del(InputStreamProxy(m_client.m_stream));
		finalize();
	}

	static if (!is(InputStream == InputStreamProxy))
	void readRawBody(scope void delegate(scope InputStream stream) @safe del)
	{
		import vibe.internal.interfaceproxy : asInterface;

		assert(!m_bodyReader, "May not mix use of readRawBody and bodyReader.");
		del(m_client.m_stream.asInterface!(.InputStream));
		finalize();
	}

	ConnectionStream switchProtocol(HTTPClientResponse res, string new_protocol)
	{
		enforce(res.statusCode == HTTPStatus.switchingProtocols, "Server did not send a 101 - Switching Protocols response");
		string *resNewProto = "Upgrade" in res.headers;
		enforce(resNewProto, "Server did not send an Upgrade header");
		enforce(!new_protocol.length || !icmp(*resNewProto, new_protocol),
			"Expected Upgrade: " ~ new_protocol ~", received Upgrade: " ~ *resNewProto);
		auto stream = createConnectionProxyStream!(typeof(m_client.m_stream), typeof(m_client.m_conn))(m_client.m_stream, m_client.m_conn);
		m_closeConn = true; // cannot reuse connection for further requests!
		return stream;
	}

	void switchProtocol(HTTPClientResponse res, string new_protocol, scope void delegate(ConnectionStream str) @safe del)
	{
		enforce(res.statusCode == HTTPStatus.switchingProtocols, "Server did not send a 101 - Switching Protocols response");
		string *resNewProto = "Upgrade" in res.headers;
		enforce(resNewProto, "Server did not send an Upgrade header");
		enforce(!new_protocol.length || !icmp(*resNewProto, new_protocol),
			"Expected Upgrade: " ~ new_protocol ~", received Upgrade: " ~ *resNewProto);
		auto stream = createConnectionProxyStream(m_client.m_stream, m_client.m_conn);
		scope (exit) () @trusted { destroy(stream); } ();
		m_closeConn = true;
		del(stream);
	}

	private bool isKeepAliveResponse(HTTPClientResponse res)
	const {
		string conn;
		if (res.httpVersion == HTTPVersion.HTTP_1_0) {
			// Workaround for non-standard-conformant servers - for example see #1780
			auto pcl = "Content-Length" in res.headers;
			if (pcl) conn = res.headers.get("Connection", "close");
			else return false; // can't use keepalive when no content length is set
		}
		else conn = res.headers.get("Connection", "keep-alive");
		return icmp(conn, "close") != 0;
	}
}
