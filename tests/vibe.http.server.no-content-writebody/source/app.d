import vibe.core.core : exitEventLoop, runApplication, runTask;
import vibe.http.client : requestHTTP;
import vibe.http.server;
import vibe.stream.operations : readAllUTF8;

import std.conv : to;

void main()
{
	auto settings = new HTTPServerSettings;
	settings.port = 0;
	settings.bindAddresses = ["127.0.0.1"];

	auto listener = listenHTTP(settings, &handler);
	scope (exit) listener.stopListening();

	runTask({
		scope (exit) exitEventLoop();

		try {
			requestHTTP("http://127.0.0.1:" ~ listener.bindAddresses[0].port.to!string,
				(scope request) {
					request.headers["Connection"] = "close";
				},
				(scope response) {
					assert(response.statusCode == HTTPStatus.noContent, response.toString());
					assert("Content-Length" !in response.headers, "204 response must not include Content-Length");
					assert(response.bodyReader.readAllUTF8() == "", "204 response must not include a body");
				}
			);
		} catch (Exception e) {
			assert(false, e.msg);
		}
	});

	runApplication();
}

void handler(scope HTTPServerRequest req, scope HTTPServerResponse res)
{
	res.writeVoidBody(HTTPStatus.noContent);
}
