module vibe.http.server;

import vibe.core.net;
import vibe.core.stream;
import vibe.http.internal.http1;
import vibe.http.internal.http2;


HTTPListener listenHTTP(alias Handler)(HTTPServerSettings settings = null)
{

}

void handleIncomingHTTPConnection(ConnectionStream connection, in ref NetworkAddress local_address)
{
	auto context = getDefaultHTTPContext(local_address);

}

void handleIncomingHTTPRequest(ConnectionStream)(ConnectionStream connection)
{

}

struct HTTPContext {
	void delegate(in ref HTTPRequestHandler request) handler;
}

// NOTE: just a possible idea for the low level api
struct HTTPRequestHandler {
	void read(alias HeaderCallback, alias BodyCallback)()
	{
		connection.readHeaders!HeaderCallback();
		connection.readBody!BodyCallback();
	}

	void write(alias HeaderCallback, alias BodyCallback)()
	{
		connection.writeHeaders!HeaderCallback();
		connection.writeBody!BodyCallback();
	}
}


private {
	HTTPContext[] s_contexts;
}

private HTTPContext getDefaultHTTPContext(in ref NetworkAddress addr)
{
	assert(false, "TODO");
}
