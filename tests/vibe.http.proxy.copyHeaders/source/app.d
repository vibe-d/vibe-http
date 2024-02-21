import vibe.core.core;
import vibe.core.log;
import vibe.http.client;
import vibe.http.server;
import vibe.http.proxy;
import vibe.http.router;
import vibe.stream.operations : readAllUTF8;
import std.algorithm : find;
import std.range.primitives : front;
import std.socket : AddressFamily;
import std.stdio;

shared static this()
{
	auto settings = new HTTPServerSettings;
	settings.port = 0;
        settings.bindAddresses = ["127.0.0.1"];

	immutable serverAddr = listenHTTP(settings, (scope req, scope res) {
		res.headers.addField("X","Y");
		res.headers.addField("X","Z");
		res.writeBody("Hello world.");
	}).bindAddresses.find!(addr => addr.family == AddressFamily.INET).front;
	
	auto router = new URLRouter;
	router.get("/", reverseProxyRequest(serverAddr.toAddressString,serverAddr.port));
	immutable proxyAddr = listenHTTP(settings, router).bindAddresses.find!(addr => addr.family == AddressFamily.INET).front;

	runTask({
		scope (exit) exitEventLoop();
		try {
			auto res = requestHTTP("http://" ~ proxyAddr.toString);
			assert(res.statusCode == HTTPStatus.ok);
			bool hadY;
			bool hadZ;
			foreach(k,v;res.headers.byKeyValue)
			{
				if ((k == "X") && (v == "Y")) hadY = true;
				if ((k == "X") && (v == "Z")) hadZ = true;
			}
			assert(hadZ);
			assert(hadY);
			assert(res.bodyReader.readAllUTF8 == "Hello world.");
		} catch (Exception e) assert(false, e.msg);
	});
	runApplication();
}
