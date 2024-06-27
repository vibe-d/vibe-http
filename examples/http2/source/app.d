/* ==== Vibe.d HTTP/2 Webserver Example ==== */
/* 	Supports both HTTP and HTTPS transport   */
/*  Transparent (WIP: exposing settings) 	 */
/* ========================================= */

import vibe.http.server;
import vibe.stream.tls;
import vibe.http.internal.http2.server : http2Callback; // ALPN negotiation
import vibe.core.core : runApplication;

/* ==== declare two handlers (could use the same one) ==== */
void handleReq(HTTPServerRequest req, HTTPServerResponse res)
@safe {
	if (res.httpVersion == HTTPVersion.HTTP_2)
		res.writeBody("Hello, you connected to "~req.path~"! This response is sent through HTTP/2\n");
	else
		res.writeBody("Hello, World! You connected through HTTP/1, try using HTTP/2!\n");
}

void tlsHandleReq(HTTPServerRequest req, HTTPServerResponse res)
@safe {
	if (req.httpVersion == HTTPVersion.HTTP_2)
		res.writeBody("Hello, you connected to "~req.path~"! This response is sent through HTTP/2 with TLS\n");
	else
		res.writeBody("Hello, World! You connected through HTTP/1 with TLS, try using HTTP/2!\n");
}

// sends a very big data frame
void bigHandleReq(size_t DIM)(HTTPServerRequest req, HTTPServerResponse res)
@trusted {
	import vibe.container.internal.appender : FixedAppender;
	import std.range : iota;

	FixedAppender!(immutable(char)[], DIM) appender;

	if (req.path == "/") {
		foreach(i; iota(1,DIM-4)) appender.put('1');
		appender.put(['O','k','!', '\n']);
		res.writeBody(appender.data);
	}
}

void main()
{
	//import vibe.core.log;
	//setLogLevel(LogLevel.trace);

/* ==== cleartext HTTP/2 support (h2c) ==== */
	auto settings = new HTTPServerSettings;
	settings.port = 8090;
	settings.bindAddresses = ["127.0.0.1"];
	listenHTTP!handleReq(settings);

/* ==== cleartext HTTP/2 support (h2c) with a heavy DATA frame ==== */
	auto bigSettings = new HTTPServerSettings;
	settings.port = 8092;
	settings.bindAddresses = ["127.0.0.1"];
	listenHTTP!(bigHandleReq!100000)(settings);

/* ========== HTTPS (h2) support ========== */
	auto tlsSettings = new HTTPServerSettings;
	tlsSettings.port = 8091;
	tlsSettings.bindAddresses = ["127.0.0.1"];

	/// setup TLS context by using cert and key in example rootdir
	tlsSettings.tlsContext = createTLSContext(TLSContextKind.server);
	tlsSettings.tlsContext.useCertificateChainFile("server.crt");
	tlsSettings.tlsContext.usePrivateKeyFile("server.key");

	// set alpn callback to support HTTP/2 protocol negotiation
	tlsSettings.tlsContext.alpnCallback(http2Callback);
	listenHTTP!tlsHandleReq(tlsSettings);

/* ========== HTTPS (h2) support with a heavy DATA frame ========== */
	auto bigTLSSettings = new HTTPServerSettings;
	bigTLSSettings.port = 8093;
	bigTLSSettings.bindAddresses = ["127.0.0.1"];

	/// setup TLS context by using cert and key in example rootdir
	bigTLSSettings.tlsContext = createTLSContext(TLSContextKind.server);
	bigTLSSettings.tlsContext.useCertificateChainFile("server.crt");
	bigTLSSettings.tlsContext.usePrivateKeyFile("server.key");

	// set alpn callback to support HTTP/2 protocol negotiation
	bigTLSSettings.tlsContext.alpnCallback(http2Callback);
	auto l = listenHTTP!(bigHandleReq!100000)(bigTLSSettings);
	scope(exit) l.stopListening();

/* ========== Run both `listenHTTP` handlers ========== */
	// UNCOMMENT to run
	runApplication();
}
