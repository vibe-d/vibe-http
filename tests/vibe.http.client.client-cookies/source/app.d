/++ dub.sdl:
	dependency "vibe-d" path=".."
+/
import vibe.core.core;
import vibe.http.client;
import vibe.http.server;
import vibe.core.log;

void main()
{
	auto settings = new HTTPServerSettings;
	settings.port = 0;
	settings.bindAddresses = ["127.0.0.1"];
	auto l = listenHTTP(settings, (req, res) {
		assert(req.cookies["clientCookie1"] == "test value");
		assert(req.cookies["clientCookie2"] == "123");
		res.writeBody("Hello, World!");
	});

	auto url = URL("http", "127.0.0.1", l.bindAddresses[0].port, InetPath("/"));

	runTask({
		try {
			auto res = requestHTTP(url, (req){
				req.setCookie("clientCookie2", "123");
				req.setCookie("clientCookie1", "test value");
			});
			assert(res.statusCode == 200, res.toString);

			res.dropBody();
			exitEventLoop();
		} catch (Exception e) assert(false, e.msg);
	});
	runApplication();
}
