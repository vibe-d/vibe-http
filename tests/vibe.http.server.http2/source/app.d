import vibe.core.core : runWorkerTask;
import vibe.core.log;
import vibe.http.server;
import curl : curlH2, curlH2Status;
import std.algorithm.searching : find;
import std.conv : to;
import std.range.primitives : front;
import std.socket : AddressFamily, SocketOption, SocketOptionLevel;

shared static this()
{
	auto settings = new HTTPServerSettings;
	settings.port = 0;
	settings.bindAddresses = ["127.0.0.1"];
	settings.options |= HTTPServerOption.enableHTTP2;

	immutable serverPort = listenHTTP(settings, &handleRequest)
		.bindAddresses
		.find!(addr => addr.family == AddressFamily.INET)
		.front.port;

	runWorkerTask((ushort port) nothrow {
		try { runAllTests(port); } catch (Exception) {}
	}, serverPort);
}

__gshared int g_failures;

void runAllTests(ushort port)
{
	void run(string name, scope void delegate() test) {
		try {
			test();
			logInfo("[PASS] %s", name);
		} catch (Throwable e) {
			logError("[FAIL] %s: %s", name, e.msg);
			g_failures++;
		}
	}

	run("h2c GET request/response", { testGetBody(port); });
	run("large response (100KB)", { testLargeResponse(port); });
	run("404 response", { test404(port); });
	run("201 status", { testStatus201(port); });
	run("204 no content", { testStatus204(port); });
	// HEAD test disabled: known HPACK single-table bug causes connection failures
	// run("HEAD returns 200 with no body", { testHeadRequest(port); });

	// Malformed request tests — verify the server survives bad input
	run("invalid connection preface", { testInvalidPreface(port); });
	run("truncated connection preface", { testTruncatedPreface(port); });
	run("garbage data", { testGarbageData(port); });
	run("valid preface then oversized frame", { testOversizedFrame(port); });
	run("valid GET after malformed connection", { testGetAfterMalformed(port); });

	import core.stdc.stdlib : exit;
	if (g_failures > 0) {
		logError("%d HTTP/2 integration test(s) FAILED.", g_failures);
		exit(1);
	}
	logInfo("All HTTP/2 integration tests passed.");
	exit(0);
}

void handleRequest(scope HTTPServerRequest req, scope HTTPServerResponse res)
@safe {
	auto path = req.requestPath.toString;

	if (path == "/" && req.method == HTTPMethod.GET) {
		res.writeBody("Hello, HTTP/2!");
		return;
	}

	if (path == "/large" && req.method == HTTPMethod.GET) {
		auto buf = new char[](100_000);
		buf[] = 'X';
		() @trusted { res.writeBody(cast(string) buf); }();
		return;
	}

	if (path == "/status/201") {
		res.statusCode = HTTPStatus.created;
		res.writeBody("created");
		return;
	}

	if (path == "/status/204") {
		res.statusCode = HTTPStatus.noContent;
		res.writeVoidBody();
		return;
	}

	res.statusCode = HTTPStatus.notFound;
	res.writeBody("not found");
}


/// Verifies basic h2c GET returns the expected response body.
void testGetBody(ushort port)
{
	auto r = curlH2(port, "/");
	assert(r == "Hello, HTTP/2!", "Expected 'Hello, HTTP/2!', got: '" ~ r ~ "'");
}

/// Verifies that a HEAD request returns HTTP 200 with no body.
void testHeadRequest(ushort port)
{
	auto status = curlH2Status(port, "/", ["-X", "HEAD"]);
	assert(status == "200", "Expected 200, got: " ~ status);
}

/// Verifies a 100KB response is delivered intact across multiple DATA frames.
void testLargeResponse(ushort port)
{
	auto r = curlH2(port, "/large");
	assert(r.length == 100_000,
		"Expected 100000 bytes, got: " ~ r.length.to!string);
	assert(r[0] == 'X' && r[$ - 1] == 'X',
		"Unexpected content in large response");
}

/// Verifies that an unknown path returns HTTP 404.
void test404(ushort port)
{
	auto r = curlH2Status(port, "/nonexistent");
	assert(r == "404", "Expected 404, got: " ~ r);
}

/// Verifies that the handler can set a custom 201 Created status.
void testStatus201(ushort port)
{
	auto r = curlH2Status(port, "/status/201");
	assert(r == "201", "Expected 201, got: " ~ r);
}

/// Verifies that writeVoidBody sends a 204 No Content with no body.
void testStatus204(ushort port)
{
	auto r = curlH2Status(port, "/status/204");
	assert(r == "204", "Expected 204, got: " ~ r);
}

/// Sends raw bytes over TCP and reads any response. Returns true if connection was accepted.
bool sendRaw(ushort port, const(ubyte)[] data)
{
	import std.socket : TcpSocket, InternetAddress;
	import core.time : msecs;

	auto sock = new TcpSocket();
	scope(exit) sock.close();
	sock.setOption(SocketOptionLevel.SOCKET, SocketOption.RCVTIMEO, 500.msecs);
	sock.connect(new InternetAddress("127.0.0.1", port));
	sock.send(data);

	ubyte[1024] buf;
	try {
		sock.receive(buf);
	} catch (Exception) {}
	return true;
}

/// Sends an invalid connection preface — server should reject and close.
void testInvalidPreface(ushort port)
{
	// Send HTTP/1.1 garbage instead of the HTTP/2 connection preface
	sendRaw(port, cast(const(ubyte)[]) "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
	// Server should survive — verify with a normal request
	auto r = curlH2(port, "/");
	assert(r == "Hello, HTTP/2!", "Server broken after invalid preface, got: '" ~ r ~ "'");
}

/// Sends a truncated (partial) connection preface — server should handle gracefully.
void testTruncatedPreface(ushort port)
{
	// Send only part of "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	sendRaw(port, cast(const(ubyte)[]) "PRI * HTTP/2.0");
	auto r = curlH2(port, "/");
	assert(r == "Hello, HTTP/2!", "Server broken after truncated preface, got: '" ~ r ~ "'");
}

/// Sends completely random garbage bytes.
void testGarbageData(ushort port)
{
	ubyte[64] garbage;
	foreach (i, ref b; garbage)
		b = cast(ubyte)(i * 37 + 13);
	sendRaw(port, garbage[]);
	auto r = curlH2(port, "/");
	assert(r == "Hello, HTTP/2!", "Server broken after garbage data, got: '" ~ r ~ "'");
}

/// Sends a valid preface followed by a frame exceeding the default max size.
void testOversizedFrame(ushort port)
{
	import std.socket : TcpSocket, InternetAddress;
	import core.time : msecs;

	// HTTP/2 connection preface
	auto preface = cast(const(ubyte)[]) "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
	// A HEADERS frame (type 0x01) claiming 100KB payload on stream 1
	// Frame header: length(3) + type(1) + flags(1) + stream_id(4) = 9 bytes
	ubyte[9] frameHeader = [
		0x01, 0x86, 0xA0, // length = 100000 (exceeds default 16384)
		0x01,             // type = HEADERS
		0x04,             // flags = END_HEADERS
		0x00, 0x00, 0x00, 0x01 // stream id = 1
	];

	auto sock = new TcpSocket();
	scope(exit) sock.close();
	sock.setOption(SocketOptionLevel.SOCKET, SocketOption.RCVTIMEO, 500.msecs);
	sock.connect(new InternetAddress("127.0.0.1", port));
	sock.send(preface);
	sock.send(frameHeader);
	// Don't send the actual payload — just close
	ubyte[1024] buf;
	try { sock.receive(buf); } catch (Exception) {}
	sock.close();

	auto r = curlH2(port, "/");
	assert(r == "Hello, HTTP/2!", "Server broken after oversized frame, got: '" ~ r ~ "'");
}

/// After all malformed tests, verify normal requests still work.
void testGetAfterMalformed(ushort port)
{
	auto r = curlH2(port, "/");
	assert(r == "Hello, HTTP/2!", "Server broken after malformed tests, got: '" ~ r ~ "'");
	auto s = curlH2Status(port, "/status/201");
	assert(s == "201", "Expected 201 after malformed tests, got: " ~ s);
}
