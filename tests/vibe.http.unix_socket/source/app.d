import vibe.core.file;
import vibe.inet.url;
import vibe.http.client;
import vibe.http.server;
import vibe.http.router;
import vibe.stream.operations;
import std.stdio;

void handleHelloRequest(scope HTTPServerRequest req, scope HTTPServerResponse res)
{
    res.writeBody("Hello, World!", "text/plain");
}

void main()
{
	version (Posix) {
		if (existsFile("/tmp/vibe.sock"))
			removeFile("/tmp/vibe.sock");

		auto router = new URLRouter;
		router.get("/hello", &handleHelloRequest);

		auto settings = new HTTPServerSettings;
		settings.bindAddresses = ["/tmp/vibe.sock"];

		listenHTTP(settings, router);

		requestHTTP("http+unix://%2ftmp%2fvibe.sock/hello", (scope req) {}, (scope res) {
			assert(res.bodyReader.readAllUTF8() == "Hello, World!");
		});

		removeFile("/tmp/vibe.sock");
	} else {
		import vibe.core.log : logInfo;
		logInfo("Skipping test on non-Posix platform.");
	}
}
