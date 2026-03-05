import vibe.core.core;
import vibe.core.log;
import vibe.http.client;
import vibe.http.server;
import vibe.stream.operations : readAllUTF8;
import std.exception : assertThrown;

shared static this()
{
	// Bind server on 127.0.0.2 (valid loopback, no external connection needed)
	auto settings = new HTTPServerSettings;
	settings.port = 0;
	settings.bindAddresses = ["127.0.0.2"];
	immutable serverAddr = listenHTTP(settings, (req, res) {
		if (req.clientAddress.toAddressString() == "127.0.0.1")
			res.writeBody("local");
		else res.writeBody("remote");
	}).bindAddresses[0];

	runTask({
		scope(exit) exitEventLoop(true);

		try {

			auto url = "http://"~serverAddr.toString;
			logInfo(url);

			string res;

			version (Windows) {}
			else {
				auto cs = new HTTPClientSettings;
				cs.networkInterface = resolveHost("127.0.0.1");
				res = requestHTTP(url, null, cs).bodyReader.readAllUTF8();
				assert(res == "local", "Unexpected reply: "~res);
			}

			auto cs2 = new HTTPClientSettings;
			cs2.networkInterface = resolveHost("127.0.0.2");
			res = requestHTTP(url, null, cs2).bodyReader.readAllUTF8();
			assert(res == "remote", "Unexpected reply: "~res);
		} catch (Exception e) assert(false, e.msg);
	});
}
