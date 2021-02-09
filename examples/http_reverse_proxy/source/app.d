import vibe.core.core;
import vibe.http.proxy;
import vibe.http.server;


void main()
{
	auto settings = new HTTPServerSettings;
	settings.port = 8080;
	settings.bindAddresses = ["::1", "127.0.0.1"];

	listenHTTPReverseProxy(settings, "vibed.org", 80);

	runApplication();
}
