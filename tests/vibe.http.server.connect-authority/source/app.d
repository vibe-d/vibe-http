import std.conv : to;

import vibe.core.core;
import vibe.core.net;
import vibe.http.common : HTTPMethod;
import vibe.http.server;
import vibe.stream.operations;

void main()
{
	auto s = new HTTPServerSettings;
	s.port = 0;
	s.bindAddresses = ["127.0.0.1"];
	immutable addr = listenHTTP(s, &handler).bindAddresses[0];

	runTask(() nothrow {
		try {
			// The target of a CONNECT request is an authority (host:port),
			// not a URL - both a name and an IP literal must reach the
			// handler unchanged
			check(addr, "example.com:443");
			check(addr, "1.1.1.1:443");
		} catch (Exception e) {
			assert(false, e.msg);
		}
		exitEventLoop();
	});

	runApplication();
}

/// Sends a CONNECT request and verifies that the handler received the
/// target as-is.
void check(NetworkAddress addr, string target)
{
	auto conn = connectTCP(addr);
	scope (exit) conn.close();

	conn.write("CONNECT " ~ target ~ " HTTP/1.1\r\n"
		~ "Host: " ~ target ~ "\r\n\r\n");

	auto res = cast(string)conn.readLine();
	assert(res == "HTTP/1.1 200 OK", res);

	while (conn.readLine().length > 0) {}
	assert(cast(string)conn.readLine() == target, target);
}

void handler(scope HTTPServerRequest req, scope HTTPServerResponse res)
{
	assert(req.method == HTTPMethod.CONNECT, req.method.to!string);
	res.writeBody(req.requestURI ~ "\r\n");
}
