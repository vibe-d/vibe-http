import vibe.core.core;
import vibe.http.server;

void main()
{
	auto settings = new HTTPServerSettings;
	settings.sessionStore = new MemorySessionStore();
	settings.port = 8080;
	settings.bindAddresses = ["::1", "127.0.0.1"];

	listenHTTP(settings, staticTemplate!("info.dt"));

	runApplication();
}
