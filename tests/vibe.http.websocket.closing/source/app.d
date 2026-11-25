import vibe.core.core;
import vibe.core.log;
import vibe.http.client;
import vibe.inet.url;
import vibe.http.server;
import vibe.http.websockets;
import std.datetime: Duration, MonoTime, msecs, seconds;
import std.algorithm: min;
import std.exception;

/**
	Tests that the WebSocket closing handshake always terminates, even when
	one of the two ends never acknowledges the close frame or when a received
	message is left unconsumed while the connection is being torn down.

	Each scenario additionally waits for the server side to finish its full
	teardown (`handleWebSocket()` returning implies that the reader task has
	been joined and the underlying connection has been closed), so that a
	broken shutdown fails the test instead of hanging it.

	The close frame acknowledgement and ping timeouts are lowered to keep the
	runtime of the test short, while still exercising the same code paths as the
	default (30s/60s) settings.
*/

// Marks whether the server side has completed its WebSocket shutdown.
__gshared bool g_shutdownDone;

void markShutdownDone() @trusted nothrow { g_shutdownDone = true; }
bool shutdownDone() @trusted nothrow { return g_shutdownDone; }

// Upper bound for the server side teardown, which is dominated by the close
// frame acknowledgement timeout configured for the scenario.
enum auto maxShutdownWait = 10.seconds;

void awaitServerShutdown(string scenario) @system
{
	immutable deadline = MonoTime.currTime + maxShutdownWait;
	while (!shutdownDone()) {
		immutable remaining = deadline - MonoTime.currTime;
		if (remaining <= Duration.zero) break;
		try sleep(min(remaining, 100.msecs));
		catch (Throwable e) logInfo("wait interrupted %s", e.msg);
	}
	enforce(shutdownDone(), "WebSocket server shutdown did not complete (" ~ scenario ~ ")");
}

private void writeFallback(scope HTTPServerResponse res) @safe nothrow
{
	try res.writeBody("nope", "text/plain");
	catch(Exception e) logInfo("writeBody %s", e.msg);
}

/// Handler: returns while a received message is still pending.
void handlePending(scope HTTPServerRequest req, scope HTTPServerResponse res) @safe nothrow
{
	if(req.requestPath.toString != "/ws") { writeFallback(res); return; }
	{
		scope(exit) markShutdownDone();
		try handleWebSocket(
			(scope ws) nothrow {
				try {
					ws.send("hello");
					// The client's "foo" arrives here and is never consumed, so
					// the reader task parks in the message hand-off while the
					// handler returns and handleWebSocket() closes the socket.
					ws.waitForData();
				} catch(Exception e) logInfo("pending handler error %s", e.msg);
			},
			req, res
		);
		catch(Exception e) logInfo("pending handleWebSocket error %s", e.msg);
	}
}

/// Handler: neither reads nor writes anything.
void handleIdle(scope HTTPServerRequest req, scope HTTPServerResponse res) @safe nothrow
{
	if(req.requestPath.toString != "/ws") { writeFallback(res); return; }
	{
		scope(exit) markShutdownDone();
		try handleWebSocket(
			(scope ws) nothrow {
				// nothing at all: both ends only perform the close handshake
			},
			req, res
		);
		catch(Exception e) logInfo("idle handleWebSocket error %s", e.msg);
	}
}

/// Handler: performs an active close twice.
void handleDoubleClose(scope HTTPServerRequest req, scope HTTPServerResponse res) @safe nothrow
{
	if(req.requestPath.toString != "/ws") { writeFallback(res); return; }
	{
		scope(exit) markShutdownDone();
		try handleWebSocket(
			(scope ws) nothrow {
				try {
					ws.send("hello");
					ws.receiveText();
					ws.close();
					ws.close();
				} catch(Exception e) logInfo("double-close handler error %s", e.msg);
			},
			req, res
		);
		catch(Exception e) logInfo("double-close handleWebSocket error %s", e.msg);
	}
}

/// Handler: lingers after the peer has hung up with data still buffered.
void handlePeerHangup(scope HTTPServerRequest req, scope HTTPServerResponse res) @safe nothrow
{
	if(req.requestPath.toString != "/ws") { writeFallback(res); return; }
	{
		scope(exit) markShutdownDone();
		try handleWebSocket(
			(scope ws) nothrow {
				try {
					// "foo" arrives here and is never consumed, "bar" stays in
					// the socket buffer. Afterwards the client tears down, so
					// the connection is passively lost with data pending.
					ws.waitForData();
					sleep(500.msecs);
				} catch(Exception e) logInfo("peer-hangup handler error %s", e.msg);
			},
			req, res
		);
		catch(Exception e) logInfo("peer-hangup handleWebSocket error %s", e.msg);
	}
}

/// Handler: waits for data until the peer stops answering its pings.
void handlePongSkip(scope HTTPServerRequest req, scope HTTPServerResponse res) @safe nothrow
{
	if(req.requestPath.toString != "/ws") { writeFallback(res); return; }
	{
		scope(exit) markShutdownDone();
		try handleWebSocket(
			(scope ws) nothrow {
				try {
					ws.send("hello");
					// The client leaves this message pending and thus cannot
					// acknowledge the server pings anymore, so the server gives
					// up on its peer via the ping timer and closes actively.
					ws.waitForData();
					sleep(1200.msecs);
				} catch(Exception e) logInfo("pong-skip handler error %s", e.msg);
			},
			req, res
		);
		catch(Exception e) logInfo("pong-skip handleWebSocket error %s", e.msg);
	}
}

/// Client: sends one message and actively closes without reading anything.
void clientPending(URL addr, const(HTTPClientSettings) settings) @system nothrow
{
	try {
		connectWebSocket(addr, (scope ws) {
			ws.send("foo");
			ws.close();
		}, settings);
		logInfo("client: connectWebSocket returned");
	} catch(Throwable e) assert(false, "pending handshake failed: " ~ e.msg);
}

/// Client: neither sends nor reads anything.
void clientIdle(URL addr, const(HTTPClientSettings) settings) @system nothrow
{
	try {
		connectWebSocket(addr, (scope ws) {
			// nothing at all
		}, settings);
		logInfo("client: connectWebSocket returned");
	} catch(Throwable e) assert(false, "idle handshake failed: " ~ e.msg);
}

/// Client: reads the reply, then closes twice.
void clientDoubleClose(URL addr, const(HTTPClientSettings) settings) @system nothrow
{
	try {
		connectWebSocket(addr, (scope ws) {
			ws.send("foo");
			ws.receiveText();
			ws.close();
			ws.close();
		}, settings);
		logInfo("client: connectWebSocket returned");
	} catch(Throwable e) assert(false, "double close failed: " ~ e.msg);
}

/// Client: sends two messages, closes and hangs up while the peer is busy.
void clientPeerHangup(URL addr, const(HTTPClientSettings) settings) @system nothrow
{
	try {
		connectWebSocket(addr, (scope ws) {
			ws.send("foo");
			ws.send("bar");   // second message stays in the socket buffer
			ws.close();
		}, settings);
		logInfo("client: connectWebSocket returned");
	} catch(Throwable e) assert(false, "peer hangup failed: " ~ e.msg);
}

/// Client: leaves a message pending and lingers, so it cannot pong.
void clientPongSkip(URL addr, const(HTTPClientSettings) settings) @system nothrow
{
	try {
		connectWebSocket(addr, (scope ws) {
			ws.send("foo");
			sleep(1200.msecs);   // never consume => our reader cannot pong
			ws.close();
		}, settings);
		logInfo("client: connectWebSocket returned");
	} catch(Throwable e) assert(false, "pong skip failed: " ~ e.msg);
}

private void test(string name, HTTPServerRequestFunctionS handler,
	void function(URL, const(HTTPClientSettings)) @system nothrow client,
	Duration pingInterval = Duration.zero, Duration closeTimeout = 500.msecs)
{
	g_shutdownDone = false;

	auto settings = new HTTPServerSettings;
	settings.port = 0;
	settings.bindAddresses = ["127.0.0.1"];
	if (pingInterval != Duration.zero) settings.webSocketPingInterval = pingInterval;
	settings.webSocketCloseTimeout = closeTimeout;

	auto client_settings = new HTTPClientSettings;
	client_settings.webSocketCloseTimeout = closeTimeout;

	auto listener = listenHTTP(settings, handler);
	immutable addr = listener.bindAddresses[0];
	auto url = URL("http://" ~ addr.toString ~ "/ws");

	// The client runs right on the main task; every call that has to wait for
	// the peer runs an event loop while it is parked, which in turn drives
	// the server side along.
	client(url, client_settings);

	awaitServerShutdown(name);
	listener.stopListening();
	logInfo("%s closing handshake terminated normally", name);
}

void main()
{
	setLogLevel(LogLevel.debug_);

	test("pending message", &handlePending, &clientPending);
	test("idle", &handleIdle, &clientIdle);
	test("double close", &handleDoubleClose, &clientDoubleClose);
	test("peer hangup", &handlePeerHangup, &clientPeerHangup);
	test("pong skip", &handlePongSkip, &clientPongSkip, 250.msecs);

	// a close timeout of Duration.max disables the forced shutdown, so both
	// ends have to acknowledge the close frame for the handshake to terminate
	test("idle (no close timeout)", &handleIdle, &clientIdle, Duration.zero, Duration.max);

	logInfo("WebSocket closing handshake test successful");
}
