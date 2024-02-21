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
	{
		auto settings = new HTTPServerSettings;
		settings.port = 80;
	        settings.bindAddresses = ["::1", "0.0.0.0"];

		immutable serverAddr = listenHTTP(settings, (scope req, scope res) {
			res.headers.addField("X","Y");
			res.headers.addField("X","Z");
			res.writeBody("Hello world.");
		}).bindAddresses.find!(addr => addr.family == AddressFamily.INET).front;
	}
	{
		auto router = new URLRouter;
		router.get("/", reverseProxyRequest("0.0.0.0",80));
		auto settings = new HTTPServerSettings;
		settings.port = 8080;
		settings.bindAddresses = ["::1", "0.0.0.0"];
		listenHTTP(settings, router);
	}

	runTask({
		scope (exit) exitEventLoop();
		try {
			auto res = requestHTTP("http://0.0.0.0:8080");
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
		logInfo("All web tests succeeded.");
	});
	runApplication();
}
