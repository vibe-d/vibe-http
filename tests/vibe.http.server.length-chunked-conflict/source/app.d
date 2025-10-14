import vibe.core.core;
import vibe.core.net;
import vibe.http.server;
import vibe.stream.operations;

// See RFC 9112 6.3.3 and https://github.com/vibe-d/vibe.d/security/advisories/GHSA-hm69-r6ch-92wx

void main()
{
	auto s1 = new HTTPServerSettings;
	s1.port = 0;
	s1.bindAddresses = ["127.0.0.1"];
	immutable serverAddr = listenHTTP(s1, &handler).bindAddresses[0];

	auto conn = connectTCP(serverAddr);
	conn.write("GET / HTTP/1.1\r\nHost: 127.0.0.1:11388\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\nfoo");
	auto res = cast(string)conn.readLine();
	assert(res == "HTTP/1.1 400 Bad Request", res);
	while (conn.readLine().length > 0) {}

	conn.close();
}

void handler(scope HTTPServerRequest req, scope HTTPServerResponse res)
{
	assert(false);
}
