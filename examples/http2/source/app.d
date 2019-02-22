import std.stdio;

import vibe.http.server;
import vibe.core.core : runApplication;    

void main()
{
	// empty handler, just to test if protocol switching works
	void handleReq(HTTPServerRequest req, HTTPServerResponse res)
	@safe {
		if (req.path == "/")
			res.writeBody("Hello, World! This response is sent through HTTP/2");
	}
	auto settings = HTTPServerSettings();
	settings.port = 8090;
	settings.bindAddresses = ["localhost"];

	listenHTTP!handleReq(settings);
	runApplication();
}
