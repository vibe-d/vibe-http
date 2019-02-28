/* ==== Vibe.d HTTP/2 Webserver Example ==== */
/* 	Supports both HTTP and HTTPS transport   */
/*  Transparent (WIP: exposing settings) 	 */
/* ========================================= */

import vibe.http.server;
import vibe.stream.tls;
import vibe.http.internal.http2.http2 : http2Callback; // ALPN negotiation
import vibe.core.core : runApplication;

/* ==== declare two handlers (could use the same one) ==== */
void handleReq(HTTPServerRequest req, HTTPServerResponse res)
@safe {
	if (req.path == "/")
		res.writeBody("Hello, World! This response is sent through HTTP/2");
}

void tlsHandleReq(HTTPServerRequest req, HTTPServerResponse res)
@safe {
	if (req.path == "/")
		res.writeBody("Hello, World! This response is sent through HTTP/2 with TLS");
}

// sends a very big data frame
void bigHandleReq(HTTPServerRequest req, HTTPServerResponse res)
@trusted {
	import vibe.utils.array : FixedAppender;
	import std.range : iota;

	FixedAppender!(immutable(char)[], 1000000) appender;

	if (req.path == "/") {
		foreach(i; iota(0,9999999999997)) appender.put('1');
		appender.put(['O','k','!']);
		res.writeBody(appender.data);
	}

}

void main()
{
	//import vibe.core.log;
	//setLogLevel(LogLevel.debug_);

/* ==== cleartext HTTP/2 support (h2c) ==== */
	auto settings = HTTPServerSettings();
	settings.port = 8090;
	settings.bindAddresses = ["localhost"];
	listenHTTP!handleReq(settings);

/* ==== cleartext HTTP/2 support (h2c) with a heavy DATA frame ==== */
	auto bigSettings = HTTPServerSettings();
	settings.port = 8092;
	settings.bindAddresses = ["localhost"];
	listenHTTP!bigHandleReq(settings);

/* ========== HTTPS (h2) support ========== */
	HTTPServerSettings tlsSettings;
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
	HTTPServerSettings bigTLSSettings;
	bigTLSSettings.port = 8093;
	bigTLSSettings.bindAddresses = ["127.0.0.1"];

	/// setup TLS context by using cert and key in example rootdir
	bigTLSSettings.tlsContext = createTLSContext(TLSContextKind.server);
	bigTLSSettings.tlsContext.useCertificateChainFile("server.crt");
	bigTLSSettings.tlsContext.usePrivateKeyFile("server.key");

	// set alpn callback to support HTTP/2 protocol negotiation
	bigTLSSettings.tlsContext.alpnCallback(http2Callback);
	listenHTTP!bigHandleReq(bigTLSSettings);

/* ========== Run both `listenHTTP` handlers ========== */
	// UNCOMMENT to run
	//runApplication();
}
