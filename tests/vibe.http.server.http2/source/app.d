import vibe.core.core : runWorkerTask;
import vibe.core.log;
import vibe.http.server;
import curl : curlH2, curlH2Status, curlSupportsH2c;
import std.algorithm.searching : find;
import std.conv : to;
import std.range.primitives : front;
import std.socket : AddressFamily, SocketOption, SocketOptionLevel;

struct H2Test {
	string name;
}

alias TestFunc = void function(ushort);

// Compile-time introspection: collect all @H2Test-annotated functions
template collectTests(alias mod)
{
	import std.traits : getUDAs, hasUDA;

	struct Entry {
		string name;
		TestFunc func;
	}

	enum Entry[] entries = () {
		Entry[] result;
		static foreach (member; __traits(allMembers, mod)) {{
			alias sym = __traits(getMember, mod, member);
			static if (is(typeof(sym) == function) && hasUDA!(sym, H2Test))
				result ~= Entry(getUDAs!(sym, H2Test)[0].name, &sym);
		}}
		return result;
	}();
}

alias allTests = collectTests!(mixin(__MODULE__));

shared static this()
{
	import core.stdc.stdlib : exit, getenv;
	import core.stdc.stdio : printf;
	import std.string : fromStringz;

	// Enable debug-level logging so server-side HTTP/2 logs are visible
	setLogLevel(LogLevel.debug_);

	auto envVal = getenv("H2_TEST");
	if (envVal is null) {
		logError("Set H2_TEST=<test-name> or H2_TEST=list");
		exit(1);
	}
	auto testName = fromStringz(envVal).idup;

	if (testName == "list") {
		static foreach (e; allTests.entries)
			printf("%.*s\n", cast(int) e.name.length, e.name.ptr);
		exit(0);
	}

	TestFunc testFunc;
	static foreach (e; allTests.entries) {
		if (testName == e.name)
			testFunc = e.func;
	}

	if (testFunc is null) {
		logError("Unknown test: %s", testName);
		exit(1);
	}

	if (!curlSupportsH2c()) {
		logInfo("curl does not support --http2-prior-knowledge, skipping.");
		exit(0);
	}

	auto settings = new HTTPServerSettings;
	settings.port = 0;
	settings.bindAddresses = ["127.0.0.1"];
	settings.options |= HTTPServerOption.enableHTTP2;

	immutable serverPort = listenHTTP(settings, &handleRequest)
		.bindAddresses
		.find!(addr => addr.family == AddressFamily.INET)
		.front.port;

	runWorkerTask((ushort port, TestFunc fn, string name) nothrow {
		import core.stdc.stdlib : exit;
		logInfo("[TEST] running '%s' on port %d", name, port);
		try {
			fn(port);
			logInfo("[PASS] %s", name);
			exit(0);
		} catch (Throwable e) {
			logError("[FAIL] %s: %s", name, e.msg);
			logError("[FAIL] %s: %s(%d)", name, e.file, e.line);
			exit(1);
		}
	}, serverPort, testFunc, testName);
}

void handleRequest(scope HTTPServerRequest req, scope HTTPServerResponse res)
@safe {
	auto path = req.requestPath.toString;

	if (path == "/" && req.method == HTTPMethod.GET) {
		res.writeBody("Hello, HTTP/2!");
		return;
	}

	if (path == "/large" && req.method == HTTPMethod.GET) {
		auto buf = new char[](10_000);
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

	if (path == "/empty") {
		res.writeBody("");
		return;
	}

	res.statusCode = HTTPStatus.notFound;
	res.writeBody("not found");
}

@H2Test("get")
void testGetBody(ushort port)
{
	auto r = curlH2(port, "/");
	assert(r == "Hello, HTTP/2!", "Expected 'Hello, HTTP/2!', got: '" ~ r ~ "'");
}

@H2Test("10kb")
void testLargeResponse(ushort port)
{
	auto r = curlH2(port, "/large");
	assert(r.length == 10_000,
		"Expected 10000 bytes, got: " ~ r.length.to!string);
	assert(r[0] == 'X' && r[$ - 1] == 'X',
		"Unexpected content in large response");
}

@H2Test("404")
void test404(ushort port)
{
	auto r = curlH2Status(port, "/nonexistent");
	assert(r == "404", "Expected 404, got: " ~ r);
}

@H2Test("201")
void testStatus201(ushort port)
{
	auto r = curlH2Status(port, "/status/201");
	assert(r == "201", "Expected 201, got: " ~ r);
}

@H2Test("204")
void testStatus204(ushort port)
{
	auto r = curlH2Status(port, "/status/204");
	assert(r == "204", "Expected 204, got: " ~ r);
}

@H2Test("empty-body")
void testEmptyBody(ushort port)
{
	auto status = curlH2Status(port, "/empty");
	assert(status == "200", "Expected 200, got: " ~ status);
}

void sendRaw(ushort port, const(ubyte)[] data)
{
	import std.socket : TcpSocket, InternetAddress;
	import core.time : msecs;

	logInfo("[sendRaw] sending %d bytes to port %d", data.length, port);
	auto sock = new TcpSocket();
	scope(exit) sock.close();
	sock.setOption(SocketOptionLevel.SOCKET, SocketOption.RCVTIMEO, 500.msecs);
	sock.connect(new InternetAddress("127.0.0.1", port));
	sock.send(data);

	ubyte[1024] buf;
	try {
		auto received = sock.receive(buf);
		logInfo("[sendRaw] received %d bytes back", received);
	} catch (Exception e) {
		logInfo("[sendRaw] receive error: %s", e.msg);
	}
}

@H2Test("bad-preface")
void testInvalidPreface(ushort port)
{
	sendRaw(port, cast(const(ubyte)[]) "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
	auto r = curlH2(port, "/");
	assert(r == "Hello, HTTP/2!", "Server broken after invalid preface, got: '" ~ r ~ "'");
}

@H2Test("truncated")
void testTruncatedPreface(ushort port)
{
	sendRaw(port, cast(const(ubyte)[]) "PRI * HTTP/2.0");
	auto r = curlH2(port, "/");
	assert(r == "Hello, HTTP/2!", "Server broken after truncated preface, got: '" ~ r ~ "'");
}

@H2Test("garbage")
void testGarbageData(ushort port)
{
	ubyte[64] garbage;
	foreach (i, ref b; garbage)
		b = cast(ubyte)(i * 37 + 13);
	sendRaw(port, garbage[]);
	auto r = curlH2(port, "/");
	assert(r == "Hello, HTTP/2!", "Server broken after garbage data, got: '" ~ r ~ "'");
}

@H2Test("oversized")
void testOversizedFrame(ushort port)
{
	import std.socket : TcpSocket, InternetAddress;
	import core.time : msecs;

	logInfo("[oversized] sending valid preface + oversized frame header to port %d", port);

	auto preface = cast(const(ubyte)[]) "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
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
	logInfo("[oversized] sent preface (%d bytes) + frame header (%d bytes), draining response",
		preface.length, frameHeader.length);
	ubyte[1024] buf;
	try { while (sock.receive(buf) > 0) {} } catch (Exception e) {
		logInfo("[oversized] drain error: %s", e.msg);
	}
	sock.close();
	logInfo("[oversized] socket closed, verifying server with normal request");

	auto r = curlH2(port, "/");
	assert(r == "Hello, HTTP/2!", "Server broken after oversized frame, got: '" ~ r ~ "'");
}
