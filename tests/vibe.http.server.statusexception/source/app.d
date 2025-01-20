import vibe.core.core;
import vibe.core.log : logInfo;
import vibe.core.net;
import vibe.http.server;
import vibe.stream.operations;
import core.time : msecs, seconds;
import std.datetime : Clock, UTC;

shared static this()
{
	auto s1 = new HTTPServerSettings;
	s1.options &= ~HTTPServerOption.errorStackTraces;
	s1.port = 0;
	s1.bindAddresses = ["127.0.0.1"];
	immutable serverAddr = listenHTTP(s1, &handler).bindAddresses[0];

	runTask({
		try {
			auto conn = connectTCP(serverAddr);
			conn.write("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
			string res = cast(string)conn.readLine();
			assert(res == "HTTP/1.1 403 This is not accessible!", res);
			while (conn.readLine().length > 0) {}
			assert(cast(string)conn.readAllUTF8() == "403 - Forbidden\n\nThis is not accessible!");
		} catch (Exception e) {
			assert(false, e.msg);
		}

		scope (exit) exitEventLoop();
	});
}

void handler(scope HTTPServerRequest req, scope HTTPServerResponse res)
{
	throw new HTTPStatusException(HTTPStatus.forbidden, "This is not accessible!");
}
