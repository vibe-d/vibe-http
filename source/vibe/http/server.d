module vibe.http.server;

public import vibe.core.net;
import vibe.core.stream;
import vibe.http.internal.http1;
import vibe.http.internal.http2.settings;

public import vibe.http.log;
public import vibe.http.common;
public import vibe.http.session;
import vibe.inet.message;
import vibe.core.file;
import vibe.core.log;
import vibe.inet.url;
import vibe.inet.webform;
import vibe.data.json;
import vibe.internal.allocator;
import vibe.internal.freelistref;
import vibe.internal.interfaceproxy : InterfaceProxy;
import vibe.stream.wrapper : ConnectionProxyStream, createConnectionProxyStream, createConnectionProxyStreamFL;
import vibe.stream.tls;
import vibe.utils.array;
import vibe.utils.string;
import vibe.stream.counting;
import vibe.stream.operations;
import vibe.stream.zlib;
import vibe.textfilter.urlencode : urlEncode, urlDecode;

import std.datetime;
import std.typecons;
import std.conv;
import std.array;
import std.algorithm;
import std.format;
import std.parallelism;
import std.exception;
import std.string;
import std.traits;
import std.encoding : sanitize;

version (VibeNoSSL) version = HaveNoTLS;
else version (Have_botan) {}
else version (Have_openssl) {}
else version = HaveNoTLS;

/**************************************************************************************************/
/* Public functions																				  */
/**************************************************************************************************/

/**
	Starts a HTTP server listening on the specified port.

	request_handler will be called for each HTTP request that is made. The
	res parameter of the callback then has to be filled with the response
	data.

	request_handler can be either HTTPServerRequestDelegate/HTTPServerRequestFunction
	or a class/struct with a member function 'handleRequest' that has the same
	signature.

	Note that if the application has been started with the --disthost command line
	switch, listenHTTP() will automatically listen on the specified VibeDist host
	instead of locally. This allows for a seamless switch from single-host to
	multi-host scenarios without changing the code. If you need to listen locally,
	use listenHTTPPlain() instead.

	Params:
		settings = Customizes the HTTP servers functionality (host string or HTTPServerSettings object)
		request_handler = This callback is invoked for each incoming request and is responsible
			for generating the response.

	Returns:
		A handle is returned that can be used to stop listening for further HTTP
		requests with the supplied settings. Another call to `listenHTTP` can be
		used afterwards to start listening again.
*/
import vibe.http.router;
HTTPListener listenHTTP(alias Handler)(HTTPServerSettings settings)
	if (is(typeof(Handler) == URLRouter) || is(typeof(Handler) : HTTPServerRequestHandler))
{
	//if (!settings)
		//settings = HTTPServerSettings;
	return listenHTTPPlain(settings, (req, res) @trusted => Handler.handleRequest(req, res));
}

import std.traits;
import std.typetuple;
HTTPListener listenHTTP(alias Handler)(HTTPServerSettings settings)
	if ((isCallable!Handler)
		&& is(ReturnType!Handler == void)
		&& is(ParameterTypeTuple!Handler == TypeTuple!(HTTPServerRequest, HTTPServerResponse)))
{
	//if (!settings)
	//settings = HTTPServerSettings;
	return listenHTTPPlain(settings, (req, res) @trusted => Handler(req, res));
}

HTTPListener listenHTTP(H)(HTTPServerSettings settings, H handler)
{
	return listenHTTP!handler(settings);
}

HTTPListener listenHTTP(H)(string bind_string, H handler)
{
	auto settings = HTTPServerSettings(bind_string);
	return listenHTTP!handler(settings);
}

/* Testing listenHTTP
 */
unittest
{
	void test()
	{
		static void testSafeFunction(HTTPServerRequest req, HTTPServerResponse res) @safe {}
		listenHTTP("0.0.0.0:8080", &testSafeFunction);
		listenHTTP(":8080", new class HTTPServerRequestHandler {
			void handleRequest(HTTPServerRequest req, HTTPServerResponse res) @safe {}
		});
		//listenHTTP(":8080", (req, res) {}); // fails on parameter type tuple

		static void testSafeFunctionS(scope HTTPServerRequest req, scope HTTPServerResponse res) @safe {}
		listenHTTP(":8080", &testSafeFunctionS);
		void testSafeDelegateS(scope HTTPServerRequest req, scope HTTPServerResponse res) @safe {}
		listenHTTP(":8080", &testSafeDelegateS);
		listenHTTP(":8080", new class HTTPServerRequestHandler {
			void handleRequest(scope HTTPServerRequest req, scope HTTPServerResponse res) @safe {}
		});
		//listenHTTP(":8080", (scope req, scope res) {}); // fails on parameter type tuple
	}
}

unittest {
	import vibe.http.router;

	void test()
	{
		auto router = new URLRouter;
		router.get("/old_url", staticRedirect("http://example.org/new_url", HTTPStatus.movedPermanently));
		HTTPServerSettings settings;
		listenHTTP!router(settings);
	}
}

unittest {
	// testing a callable as request handler
	void handleRequest (HTTPServerRequest req, HTTPServerResponse res)
	@safe {
		if (req.path == "/")
		res.writeBody("Hello, World! Delegate");
	}

	auto settings = HTTPServerSettings();
	settings.port = 8060;
	settings.bindAddresses = ["localhost"];

	listenHTTP!handleRequest(settings);
}



/**
	Provides a HTTP request handler that responds with a static redirection to the specified URL.

	Params:
		url = The URL to redirect to
		status = Redirection status to use $(LPAREN)by default this is $(D HTTPStatus.found)$(RPAREN).

	Returns:
		Returns a $(D HTTPServerRequestDelegate) that performs the redirect
*/
HTTPServerRequestDelegate staticRedirect(string url, HTTPStatus status = HTTPStatus.found)
@safe {
	return (HTTPServerRequest req, HTTPServerResponse res){
		res.redirect(url, status);
	};
}
/// ditto
HTTPServerRequestDelegate staticRedirect(URL url, HTTPStatus status = HTTPStatus.found)
@safe {
	return (HTTPServerRequest req, HTTPServerResponse res){
		res.redirect(url, status);
	};
}

///

/**
	Sets a VibeDist host to register with.
*/
void setVibeDistHost(string host, ushort port)
@safe {
	s_distHost = host;
	s_distPort = port;
}


/**
	Renders the given Diet template and makes all ALIASES available to the template.

	You can call this function as a pseudo-member of `HTTPServerResponse` using
	D's uniform function call syntax.

	See_also: `diet.html.compileHTMLDietFile`

	Examples:
		---
		string title = "Hello, World!";
		int pageNumber = 1;
		res.render!("mytemplate.dt", title, pageNumber);
		---
*/
@property void render(string template_file, ALIASES...)(HTTPServerResponse res)
{
	res.contentType = "text/html; charset=UTF-8";
	version (VibeUseOldDiet)
		pragma(msg, "VibeUseOldDiet is not supported anymore. Please undefine in the package recipe.");
	import vibe.stream.wrapper : streamOutputRange;
	import diet.html : compileHTMLDietFile;
	auto output = streamOutputRange!1024(res.bodyWriter);
	compileHTMLDietFile!(template_file, ALIASES, DefaultDietFilters)(output);
}

version (Have_diet_ng)
{
	import diet.traits;

	/**
		Provides the default `css`, `javascript`, `markdown` and `htmlescape` filters
	 */
	@dietTraits
	struct DefaultDietFilters {
		import diet.html : HTMLOutputStyle;
		import std.string : splitLines;

		version (VibeOutputCompactHTML) enum HTMLOutputStyle htmlOutputStyle = HTMLOutputStyle.compact;
		else enum HTMLOutputStyle htmlOutputStyle = HTMLOutputStyle.pretty;

		static string filterCss(I)(I text, size_t indent = 0)
		{
			auto lines = splitLines(text);

			string indent_string = "\n";
			while (indent-- > 0) indent_string ~= '\t';

			string ret = indent_string~"<style type=\"text/css\"><!--";
			indent_string = indent_string ~ '\t';
			foreach (ln; lines) ret ~= indent_string ~ ln;
			indent_string = indent_string[0 .. $-1];
			ret ~= indent_string ~ "--></style>";

			return ret;
		}


		static string filterJavascript(I)(I text, size_t indent = 0)
		{
			auto lines = splitLines(text);

			string indent_string = "\n";
			while (indent-- > 0) indent_string ~= '\t';

			string ret = indent_string~"<script type=\"application/javascript\">";
			ret ~= indent_string~'\t' ~ "//<![CDATA[";
			foreach (ln; lines) ret ~= indent_string ~ '\t' ~ ln;
			ret ~= indent_string ~ '\t' ~ "//]]>" ~ indent_string ~ "</script>";

			return ret;
		}

		static string filterMarkdown(I)(I text)
		{
			import vibe.textfilter.markdown : markdown = filterMarkdown;
			// TODO: indent
			return markdown(text);
		}

		static string filterHtmlescape(I)(I text)
		{
			import vibe.textfilter.html : htmlEscape;
			// TODO: indent
			return htmlEscape(text);
		}

		static this()
		{
			filters["css"] = (input, scope output) { output(filterCss(input)); };
			filters["javascript"] = (input, scope output) { output(filterJavascript(input)); };
			filters["markdown"] = (input, scope output) { output(filterMarkdown(() @trusted { return cast(string)input; } ())); };
			filters["htmlescape"] = (input, scope output) { output(filterHtmlescape(input)); };
		}

		static SafeFilterCallback[string] filters;
	}


	unittest {
		static string compile(string diet)() {
			import std.array : appender;
			import std.string : strip;
			import diet.html : compileHTMLDietString;
			auto dst = appender!string;
			dst.compileHTMLDietString!(diet, DefaultDietFilters);
			return strip(cast(string)(dst.data));
		}

		assert(compile!":css .test" == "<style type=\"text/css\"><!--\n\t.test\n--></style>");
		assert(compile!":javascript test();" == "<script type=\"application/javascript\">\n\t//<![CDATA[\n\ttest();\n\t//]]>\n</script>");
		assert(compile!":markdown **test**" == "<p><strong>test</strong>\n</p>");
		assert(compile!":htmlescape <test>" == "&lt;test&gt;");
		assert(compile!":css !{\".test\"}" == "<style type=\"text/css\"><!--\n\t.test\n--></style>");
		assert(compile!":javascript !{\"test();\"}" == "<script type=\"application/javascript\">\n\t//<![CDATA[\n\ttest();\n\t//]]>\n</script>");
		assert(compile!":markdown !{\"**test**\"}" == "<p><strong>test</strong>\n</p>");
		assert(compile!":htmlescape !{\"<test>\"}" == "&lt;test&gt;");
		assert(compile!":javascript\n\ttest();" == "<script type=\"application/javascript\">\n\t//<![CDATA[\n\ttest();\n\t//]]>\n</script>");
	}
}


/**
  Creates a HTTPServerRequest suitable for writing unit tests.
 */
HTTPServerRequest createTestHTTPServerRequest(URL url, HTTPMethod method = HTTPMethod.GET, InputStream data = null)
@safe {
	InetHeaderMap headers;
	return createTestHTTPServerRequest(url, method, headers, data);
}
/// ditto
HTTPServerRequest createTestHTTPServerRequest(URL url, HTTPMethod method, InetHeaderMap headers, InputStream data = null)
@safe {
	auto tls = url.schema == "https";
	auto ret = HTTPServerRequest(Clock.currTime(UTC()), url.port ? url.port : tls ? 443 : 80);
	ret.requestPath = url.path;
	ret.queryString = url.queryString;
	ret.username = url.username;
	ret.password = url.password;
	ret.requestURI = url.localURI;
	ret.method = method;
	ret.tls = tls;
	//ret.headers = headers; // TODO compiler error
	ret.bodyReader = data;
	return ret;
}

/**
	  Creates a HTTPServerResponse suitable for writing unit tests.
	  */
HTTPServerResponse createTestHTTPServerResponse(OutputStream data_sink = null, SessionStore session_store = null)
@safe {
	import vibe.stream.wrapper;

	HTTPServerSettings settings;
	if (session_store) {
		//settings = HTTPServerSettings;
		settings.sessionStore = session_store;
	}
	if (!data_sink) data_sink = new NullOutputStream;
	auto stream = createProxyStream(Stream.init, data_sink);
	auto ret = HTTPServerResponse(stream, null, settings, () @trusted { return vibeThreadAllocator(); } ());
	return ret;
}


/**************************************************************************************************/
/* Public types																					  */
/**************************************************************************************************/

/// Interface for class based request handlers
interface HTTPServerRequestHandler {
	/// Handles incoming HTTP requests
	void handleRequest(HTTPServerRequest req, HTTPServerResponse res) @safe ;
}


alias HTTPContext = HTTPServerContext;

/// Delegate based request handler
alias HTTPServerRequestDelegate = void delegate(HTTPServerRequest req, HTTPServerResponse res) @safe;
/// Static function based request handler
alias HTTPServerRequestFunction = void function(HTTPServerRequest req, HTTPServerResponse res) @safe;


/// Aggregates all information about an HTTP error status.
struct HTTPServerErrorInfo {
	/// The HTTP status code
	int code;
	/// The error message
	string message;
	/// Extended error message with debug information such as a stack trace
	string debugMessage;
	/// The error exception, if any
	Throwable exception;
}


/// Delegate type used for user defined error page generator callbacks.
alias HTTPServerErrorPageHandler = void delegate(HTTPServerRequest req, HTTPServerResponse res, HTTPServerErrorInfo error) @safe;


private enum HTTPServerOptionImpl {
	none					  = 0,
	errorStackTraces		  = 1<<7,
	reusePort				  = 1<<8,
	distribute				  = 1<<9 // deprecated
}

// TODO: Should be turned back into an enum once the deprecated symbols can be removed
/**
	  Specifies optional features of the HTTP server.

	  Disabling unneeded features can speed up the server or reduce its memory usage.

	  Note that the options `parseFormBody`, `parseJsonBody` and `parseMultiPartBody`
	  will also drain the `HTTPServerRequest.bodyReader` stream whenever a request
	  body with form or JSON data is encountered.
*/
struct HTTPServerOption {
	static enum none					  = HTTPServerOptionImpl.none;
	deprecated("This is done lazily. It will be removed in 0.9.")
	static enum parseURL				  = none;
	deprecated("This is done lazily. It will be removed in 0.9.")
	static enum parseQueryString		  = none;
	deprecated("This is done lazily. It will be removed in 0.9.")
	static enum parseFormBody			  = none;
	deprecated("This is done lazily. It will be removed in 0.9.")
	static enum parseJsonBody			  = none;
	deprecated("This is done lazily. It will be removed in 0.9.")
	static enum parseMultiPartBody		  = none;
	/* Deprecated: Distributes request processing among worker threads

		Note that this functionality assumes that the request handler
		is implemented in a thread-safe way. However, the D type system
		is bypassed, so that no static verification takes place.

		For this reason, it is recommended to instead use
		`vibe.core.core.runWorkerTaskDist` and call `listenHTTP`
		from each task/thread individually. If the `reusePort` option
		is set, then all threads will be able to listen on the same port,
		with the operating system distributing the incoming connections.

		If possible, instead of threads, the use of separate processes
		is more robust and often faster. The `reusePort` option works
		the same way in this scenario.
	*/
	deprecated("Use runWorkerTaskDist or start threads separately. It will be removed in 0.9.")
	static enum distribute				  = HTTPServerOptionImpl.distribute;
	/* Enables stack traces (`HTTPServerErrorInfo.debugMessage`).

		Note that generating the stack traces are generally a costly
		operation that should usually be avoided in production
		environments. It can also reveal internal information about
		the application, such as function addresses, which can
		help an attacker to abuse possible security holes.
	*/
	static enum errorStackTraces		  = HTTPServerOptionImpl.errorStackTraces;
	/// Enable port reuse in `listenTCP()`
	static enum reusePort				  = HTTPServerOptionImpl.reusePort;

	/* The default set of options.

		Includes all parsing options, as well as the `errorStackTraces`
		option if the code is compiled in debug mode.
	*/
	static enum defaults = () { debug return HTTPServerOptionImpl.errorStackTraces; else return HTTPServerOptionImpl.none; } ().HTTPServerOption;

	deprecated("None has been renamed to none.")
	static enum None = none;
	deprecated("This is done lazily. It will be removed in 0.9.")
	static enum ParseURL = none;
	deprecated("This is done lazily. It will be removed in 0.9.")
	static enum ParseQueryString = none;
	deprecated("This is done lazily. It will be removed in 0.9.")
	static enum ParseFormBody = none;
	deprecated("This is done lazily. It will be removed in 0.9.")
	static enum ParseJsonBody = none;
	deprecated("This is done lazily. It will be removed in 0.9.")
	static enum ParseMultiPartBody = none;
	deprecated("This is done lazily. It will be removed in 0.9.")
	static enum ParseCookies = none;

	HTTPServerOptionImpl x;
	alias x this;
}


/**
	Contains all settings for configuring a basic HTTP server.

	The defaults are sufficient for most normal uses.
*/
struct HTTPServerSettings {
	/** The port on which the HTTP server is listening.

		The default value is 80. If you are running a TLS enabled server you may want to set this
		to 443 instead.

		Using a value of `0` instructs the server to use any available port on
		the given `bindAddresses` the actual addresses and ports can then be
		queried with `TCPListener.bindAddresses`.
	*/
	ushort port = 80;

	/** The interfaces on which the HTTP server is listening.

		By default, the server will listen on all IPv4 and IPv6 interfaces.
	*/
	string[] bindAddresses = ["::", "0.0.0.0"];

	/** Determines the server host name.

		If multiple servers are listening on the same port, the host name will determine which one
		gets a request.
	*/
	string hostName;

	/** Configures optional features of the HTTP server

		Disabling unneeded features can improve performance or reduce the server
		load in case of invalid or unwanted requests (DoS). By default,
		HTTPServerOption.defaults is used.
	*/
	HTTPServerOptionImpl options = HTTPServerOption.defaults;

	/** Time of a request after which the connection is closed with an error; not supported yet

		The default limit of 0 means that the request time is not limited.
	*/
	Duration maxRequestTime = 0.seconds;

	/** Maximum time between two request on a keep-alive connection

		The default value is 10 seconds.
	*/
	Duration keepAliveTimeout = 10.seconds;

	/// Maximum number of transferred bytes per request after which the connection is closed with
	/// an error
	ulong maxRequestSize = 2097152;


	///	Maximum number of transferred bytes for the request header. This includes the request line
	/// the url and all headers.
	ulong maxRequestHeaderSize = 8192;

	/// Sets a custom handler for displaying error pages for HTTP errors
	@property HTTPServerErrorPageHandler errorPageHandler() @safe { return errorPageHandler_; }
	/// ditto
	@property void errorPageHandler(HTTPServerErrorPageHandler del) @safe { errorPageHandler_ = del; }
	/// Scheduled for deprecation - use a `@safe` callback instead.
	@property void errorPageHandler(void delegate(HTTPServerRequest, HTTPServerResponse, HTTPServerErrorInfo) @system del)
	@system {
		this.errorPageHandler = (req, res, err) @trusted { del(req, res, err); };
	}

	void handleErrorPage(HTTPServerRequest req, HTTPServerResponse res, HTTPServerErrorInfo err)
	@safe {
		errorPageHandler_(req, res, err);
	}

	private HTTPServerErrorPageHandler errorPageHandler_ = null;

	/// If set, a HTTPS server will be started instead of plain HTTP.
	TLSContext tlsContext;

	/// Session management is enabled if a session store instance is provided
	SessionStore sessionStore;
	string sessionIdCookie = "vibe.session_id";

	///
	import vibe.core.core : vibeVersionString;
	string serverString = "vibe.d/" ~ vibeVersionString;

	/** Specifies the format used for the access log.

		The log format is given using the Apache server syntax. By default NCSA combined is used.

		---
		"%h - %u %t \"%r\" %s %b \"%{Referer}i\" \"%{User-Agent}i\""
		---
	*/
	string accessLogFormat = "%h - %u %t \"%r\" %s %b \"%{Referer}i\" \"%{User-Agent}i\"";

	/// Spefifies the name of a file to which access log messages are appended.
	string accessLogFile = "";

	/// If set, access log entries will be output to the console.
	bool accessLogToConsole = false;

	/** Specifies a custom access logger instance.
	*/
	HTTPLogger accessLogger;

	/// Returns a duplicate of the settings object.
	@property HTTPServerSettings dup()
	@safe {
		//auto ret = HTTPServerSettings;
		HTTPServerSettings ret;
		foreach (mem; __traits(allMembers, HTTPServerSettings)) {
			static if (mem == "sslContext") {}
			else static if (mem == "bindAddresses") ret.bindAddresses = bindAddresses.dup;
			else static if (__traits(compiles, __traits(getMember, ret, mem) = __traits(getMember, this, mem)))
				__traits(getMember, ret, mem) = __traits(getMember, this, mem);
		}
		return ret;
	}

	/// Disable support for VibeDist and instead start listening immediately.
	bool disableDistHost = false;

	/** Responds to "Accept-Encoding" by using compression if possible.

		Compression can also be manually enabled by setting the
		"Content-Encoding" header of the HTTP response appropriately before
		sending the response body.

		This setting is disabled by default. Also note that there are still some
		known issues with the GZIP compression code.
	*/
	bool useCompressionIfPossible = false;


	/** Interval between WebSocket ping frames.

		The default value is 60 seconds; set to Duration.zero to disable pings.
	*/
	Duration webSocketPingInterval = 60.seconds;

	/** Constructs a new settings object with default values.
	*/
	//this() @safe {}

	/** Constructs a new settings object with a custom bind interface and/or port.

		The syntax of `bind_string` is `[<IP address>][:<port>]`, where either of
		the two parts can be left off. IPv6 addresses must be enclosed in square
		brackets, as they would within a URL.

		Throws:
			An exception is thrown if `bind_string` is malformed.
	*/
	this(string bind_string)
	@safe {
		//this();

		if (bind_string.startsWith('[')) {
			auto idx = bind_string.indexOf(']');
			enforce(idx > 0, "Missing closing bracket for IPv6 address.");
			bindAddresses = [bind_string[1 .. idx]];
			bind_string = bind_string[idx+1 .. $];

			enforce(bind_string.length == 0 || bind_string.startsWith(':'),
				"Only a colon may follow the IPv6 address.");
		}

		auto idx = bind_string.indexOf(':');
		if (idx < 0) {
			if (bind_string.length > 0) bindAddresses = [bind_string];
		} else {
			if (idx > 0) bindAddresses = [bind_string[0 .. idx]];
			port = bind_string[idx+1 .. $].to!ushort;
		}
	}

	///
	unittest {
		auto s = HTTPServerSettings(":8080");
		assert(s.bindAddresses == ["::", "0.0.0.0"]); // default bind addresses
		assert(s.port == 8080);

		s = HTTPServerSettings("123.123.123.123");
		assert(s.bindAddresses == ["123.123.123.123"]);
		assert(s.port == 80);

		s = HTTPServerSettings("[::1]:443");
		assert(s.bindAddresses == ["::1"]);
		assert(s.port == 443);
	}
}


/*
	Options altering how sessions are created.

	Multiple values can be or'ed together.

	See_Also: HTTPServerResponse.startSession
*/
enum SessionOption {
	/// No options.
	none = 0,

	/* Instructs the browser to disallow accessing the session ID from JavaScript.

		See_Also: Cookie.httpOnly
	*/
	httpOnly = 1<<0,

	/* Instructs the browser to disallow sending the session ID over
		unencrypted connections.

		By default, the type of the connection on which the session is started
		will be used to determine if secure or noSecure is used.

		See_Also: noSecure, Cookie.secure
	*/
	secure = 1<<1,

	/* Instructs the browser to allow sending the session ID over unencrypted
		connections.

		By default, the type of the connection on which the session is started
		will be used to determine if secure or noSecure is used.

		See_Also: secure, Cookie.secure
	*/
	noSecure = 1<<2
}


/**
	Represents a HTTP request as received by the server side.
 */
struct HTTPServerRequest {
	private HTTPServerRequestData* m_data;

	this (HTTPServerRequestData* data)
	@safe {
		m_data = data;
	}

	this (SysTime reqtime, ushort bindPort)
	@safe {
		auto data = new HTTPServerRequestData(reqtime, bindPort);
		() @trusted { m_data = data; } ();
	}

	package {
		@property scope const(HTTPServerSettings) serverSettings()
		@safe {
			return m_data.serverSettings;
		}
	}

	public {
		import vibe.utils.dictionarylist;
		DictionaryList!(string, true, 8) params;

		@property scope string requestURI() const @safe { return m_data.requestURI; }
		// ditto
		@property void requestURI(string uri) @safe { m_data.requestURI = uri; }

		@property scope string peer() @safe { return m_data.peer; }

		@property scope CookieValueMap cookies() @safe { return	 m_data.cookies; }

		@property scope FormFields query() @safe { return m_data.query; }

		@property scope Json json() @safe { return m_data.json; }

		@property scope FormFields form() @safe { return m_data.form; }

		@property scope FilePartFormFields files() @safe { return m_data.files; }

		@property scope SysTime timeCreated() const @safe { return m_data.timeCreated; }

		@property scope URL fullURL() const @safe { return m_data.fullURL; }

		@property scope string rootDir() const @safe { return m_data.rootDir; }

		@property scope string username() const @safe { return m_data.username; }

		// ditto
		@property void username(string name)
		@safe { m_data.username = name; }

		@property scope string path() @safe { return m_data.path; }

		@property scope InetHeaderMap headers() @safe { return m_data.headers; }

		@property scope bool persistent() const @safe { return m_data.persistent; }

		@property scope string queryString() const @safe { return m_data.queryString; }

		// ditto
		@property void queryString(string qstr)
		@safe { m_data.queryString = qstr; }

		@property scope string requestURL() const @safe { return m_data.requestURL; }

		@property scope HTTPVersion httpVersion() const @safe { return m_data.httpVersion; }

		// ditto
		@property void httpVersion(HTTPVersion hver)
		@safe { m_data.httpVersion = hver; }

		@property scope string host() const @safe { return m_data.host; }

		// ditto
		@property void host(string v) @safe { m_data.headers["Host"] = v; }

		@property scope string contentType() const @safe{ return m_data.contentType; }

		// ditto
		@property void contentType(string ct)
		@safe { m_data.headers["Content-Type"] = ct; }

		@property scope string contentTypeParameters() const
		@safe { return m_data.contentTypeParameters; }

		@property scope NetworkAddress clientAddress() const
		@safe { return m_data.clientAddress; }

		// ditto
		@property void clientAddress(NetworkAddress naddr)
		@safe { m_data.clientAddress = naddr; }

		@property scope bool tls() const @safe { return m_data.tls; }

		// ditto
		@property void tls(bool val)
		@safe { m_data.tls = val; }

		@property scope HTTPMethod method() const @safe { return m_data.method; }

		// ditto
		@property void method(HTTPMethod m) @safe { m_data.method = m; }

		@property scope HTTPServerSettings m_settings()
		@safe { return m_data.m_settings; }

		// ditto
		@property void m_settings(HTTPServerSettings settings)
		@safe { m_data.m_settings = settings; }

		@property scope InputStream bodyReader() @safe { return m_data.bodyReader; }

		// ditto
		@property void bodyReader(InputStream inStr)
		@safe { m_data.bodyReader = inStr; }

		@property scope string password() const @safe{ return m_data.password; }

		// ditto
		@property void password(string pwd)
		@safe{ m_data.password = pwd; }

		@property scope Session session() @safe { return m_data.session; }

		// ditto
		@property void session(Session session)
		@safe { m_data.session = session; }


		@property scope InetPath requestPath() const @safe { return m_data.requestPath; }

		// ditto
		@property void requestPath(InetPath reqpath)
		@safe { m_data.requestPath = reqpath; }

		@property scope FilePartFormFields _files() @safe { return m_data._files; }

		@property scope bool noLog() const @safe { return m_data.noLog; }

		@property scope TLSCertificateInformation clientCertificate()
		@safe {
			return m_data.clientCertificate;
		}

		@property void clientCertificate(TLSCertificateInformation cert)
		@safe {
			m_data.clientCertificate = cert;
		}
	}
}

/**
	Represents a HTTP response as sent from the server side.
*/
struct HTTPServerResponse {
	@safe:

	private HTTPServerResponseData *m_data;

	this (HTTPServerResponseData *data)
	{
		m_data = data;
	}

	static if (!is(Stream == InterfaceProxy!Stream)) {
		this(Stream conn, ConnectionStream raw_connection, HTTPServerSettings settings, IAllocator req_alloc)
		@safe {
			this(InterfaceProxy!Stream(conn), InterfaceProxy!ConnectionStream(raw_connection), settings, req_alloc);
		}
	}

	this(InterfaceProxy!Stream conn, InterfaceProxy!ConnectionStream raw_connection, HTTPServerSettings settings, IAllocator req_alloc)
	{
		HTTPServerResponseData *data = new HTTPServerResponseData(conn, raw_connection, settings, req_alloc);
		this(data);
	}

	@property scope HTTPVersion httpVersion() { return m_data.httpVersion; }
	@property void httpVersion(HTTPVersion h) { m_data.httpVersion = h; }

	@property scope int statusCode() { return m_data.statusCode; }

	@property scope string statusPhrase() { return m_data.statusPhrase; }

	@property scope InetHeaderMap headers() { return m_data.headers; }

	@property scope Cookie[string] cookies() { return m_data.cookies; }

	@property string toString() { return m_data.toString(); }

	@property scope string contentType() { return m_data.contentType(); }
	@property void contentType(string ct) { return m_data.contentType(ct); }

	@property scope SysTime timeFinalized() const { return m_data.timeFinalized; }

	@property scope bool headerWritten() const { return m_data.headerWritten; }

	@property scope bool isHeadResponse() const { return m_data.isHeadResponse(); }

	@property scope bool tls() const { return m_data.tls(); }

	@property void tls(bool v) { m_data.m_tls = v; }

	@property void m_settings(HTTPServerSettings s) { m_data.m_settings = s; }

	@property void m_session(Session s) { m_data.m_session = s; }

	@property void m_isHeadResponse(bool b) { m_data.m_isHeadResponse = b; }

	void setStatusCode(int v) { m_data.statusCode = v; }

	void writeBody(in ubyte[] data, string contentType = null)
	{
		m_data.writeBody(data, contentType);
	}
	void writeBody(scope InputStream data, string content_type = null)
	{
		m_data.writeBody(data, content_type);
	}
	void writeBody(string data, string content_type = null)
	{
		m_data.writeBody(data, content_type);
	}
	void writeBody(string data, int status, string content_type = null)
	{
		m_data.writeBody(data, status, content_type);
	}

	void writeRawBody(RandomAccessStream)(RandomAccessStream stream) @safe
		if (isRandomAccessStream!RandomAccessStream)
	{
		m_data.writeRawBody(stream);
	}
	/// ditto
	void writeRawBody(InputStream)(InputStream stream, size_t num_bytes = 0) @safe
		if (isInputStream!InputStream && !isRandomAccessStream!InputStream)
	{
		m_data.writeRawBody(stream, num_bytes);
	}
	/// ditto
	void writeRawBody(RandomAccessStream)(RandomAccessStream stream, int status) @safe
		if (isRandomAccessStream!RandomAccessStream)
	{
		m_data.writeRawBody(stream, status);
	}
	/// ditto
	void writeRawBody(InputStream)(InputStream stream, int status, size_t num_bytes = 0) @safe
		if (isInputStream!InputStream && !isRandomAccessStream!InputStream)
	{
		m_data.writeRawBody(stream, status, num_bytes);
	}

	/// Writes a JSON message with the specified status
	void writeJsonBody(T)(T data, int status, bool allow_chunked = false)
	{
		m_data.writeJsonBody(data, status, allow_chunked);
	}
	/// ditto
	void writeJsonBody(T)(T data, int status, string content_type, bool allow_chunked = false)
	{
		m_data.writeJsonBody(data, status, content_type, allow_chunked);
	}

	/// ditto
	void writeJsonBody(T)(T data, string content_type, bool allow_chunked = false)
	{
		m_data.writeJsonBody(data, content_type, allow_chunked);
	}
	/// ditto
	void writeJsonBody(T)(T data, bool allow_chunked = false)
	{
		m_data.writeJsonBody(data, allow_chunked);
	}
	/// ditto
	void writePrettyJsonBody(T)(T data, bool allow_chunked = false)
	{
		m_data.writePrettyJsonBody(data, allow_chunked);
	}

	@property void writeVoidBody()
	{
		m_data.writeVoidBody();
	}

	@property InterfaceProxy!OutputStream bodyWriter()
	{
		return m_data.bodyWriter;
	}

	@property void bodyWriter(T)(ref T writer)
	{
		m_data.bodyWriter(writer);
	}

	/** Sends a redirect request to the client.

		Params:
			url = The URL to redirect to
			status = The HTTP redirect status (3xx) to send - by default this is $(D HTTPStatus.found)
	*/
	void redirect(T)(T url, int status = HTTPStatus.Found)
	if(is(typeof(url) == string) || is(typeof(url) == URL))
	{
		m_data.redirect(url, status);
	}

	/** Special method sending a SWITCHING_PROTOCOLS response to the client.

		Notice: For the overload that returns a `ConnectionStream`, it must be
			ensured that the returned instance doesn't outlive the request
			handler callback.

		Params:
			protocol = The protocol set in the "Upgrade" header of the response.
				Use an empty string to skip setting this field.
	*/
	scope ConnectionStream switchProtocol(string protocol)
	{
		return m_data.switchProtocol(protocol);
	}
	/// ditto
	void switchProtocol(string protocol, scope void delegate(scope ConnectionStream) @safe del)
	{
		m_data.switchProtocol(protocol, del);
	}
	/// ditto
	package void switchToHTTP2(HANDLER)(HANDLER handler, HTTP2ServerContext context)
	@safe {
		m_data.switchToHTTP2(handler, context);
	}

	// Send a BadRequest and close connection (failed switch to HTTP/2)
	package void sendBadRequest() {
		m_data.sendBadRequest();
	}

	/** Special method for handling CONNECT proxy tunnel

		Notice: For the overload that returns a `ConnectionStream`, it must be
			ensured that the returned instance doesn't outlive the request
			handler callback.
	*/
	scope ConnectionStream connectProxy()
	{
		return m_data.connectProxy();
	}
	/// ditto
	void connectProxy(scope void delegate(scope ConnectionStream) @safe del)
	{
		m_data.connectProxy(del);
	}

	/** Sets the specified cookie value.

		Params:
			name = Name of the cookie
			value = New cookie value - pass null to clear the cookie
			path = Path (as seen by the client) of the directory tree in which the cookie is visible
	*/
	scope Cookie setCookie(string name, string value, string path = "/", Cookie.Encoding encoding = Cookie.Encoding.url)
	{
		return m_data.setCookie(name, value, path, encoding);
	}

	/**
		Initiates a new session.

		The session is stored in the SessionStore that was specified when
		creating the server. Depending on this, the session can be persistent
		or temporary and specific to this server instance.
	*/
	scope Session startSession(string path = "/", SessionOption options = SessionOption.httpOnly)
	{
		return m_data.startSession(path, options);
	}

	/**
		Terminates the current session (if any).
	*/
	void terminateSession()
	{
		m_data.terminateSession();
	}

	@property scope ulong bytesWritten() const { return m_data.bytesWritten; }

	/**
		Waits until either the connection closes, data arrives, or until the
		given timeout is reached.

		Returns:
			$(D true) if the connection was closed and $(D false) if either the
			timeout was reached, or if data has arrived for consumption.

		See_Also: `connected`
	*/
	bool waitForConnectionClose(Duration timeout = Duration.max)
	{
		return m_data.waitForConnectionClose(timeout);
	}

	/**
		Determines if the underlying connection is still alive.

		Returns $(D true) if the remote peer is still connected and $(D false)
		if the remote peer closed the connection.

		See_Also: `waitForConnectionClose`
	*/
	@property bool connected() const { return m_data.connected;	}

	/**
		Finalizes the response. This is usually called automatically by the server.

		This method can be called manually after writing the response to force
		all network traffic associated with the current request to be finalized.
		After the call returns, the `timeFinalized` property will be set.
	*/
	void finalize() { m_data.finalize(); }
}


/**
	Represents the request listener for a specific `listenHTTP` call.

	This struct can be used to stop listening for HTTP requests at runtime.
*/
struct HTTPListener {
	private {
		size_t[] m_virtualHostIDs;
	}

	private this(size_t[] ids) @safe { m_virtualHostIDs = ids; }

	@property NetworkAddress[] bindAddresses()
	{
		NetworkAddress[] ret;
		foreach (l; s_contexts)
			if (l.m_virtualHosts.canFind!(v => m_virtualHostIDs.canFind(v.id))) {
				NetworkAddress a;
				a = resolveHost(l.bindAddress);
				a.port = l.bindPort;
				ret ~= a;
			}
		return ret;
	}

	/** Stops handling HTTP requests and closes the TCP listening port if
		possible.
	*/
	void stopListening()
	@safe {
		import std.algorithm : countUntil;

		foreach (vhid; m_virtualHostIDs) {
			foreach (lidx, l; s_contexts) {
				if (l.removeVirtualHost(vhid)) {
					if (!l.hasVirtualHosts) {
						l.stopListening();
						logInfo("Stopped to listen for HTTP%s requests on %s:%s", l.tlsContext ? "S": "", l.bindAddress, l.bindPort);
						logInfo("Stopped to listen for HTTP%s requests on %s:%s", "", l.bindAddress, l.bindPort);
						s_contexts = s_contexts[0 .. lidx] ~ s_contexts[lidx+1 .. $];
					}
				}
				break;
			}
		}
	}
}

/** Represents a single HTTP server port.

	This class defines the incoming interface, port, and TLS configuration of
	the public server port. The public server port may differ from the local
	one if a reverse proxy of some kind is facing the public internet and
	forwards to this HTTP server.

	Multiple virtual hosts can be configured to be served from the same port.
	Their TLS settings must be compatible and each virtual host must have a
*/
final class HTTPServerContext {
	struct VirtualHost {
		HTTPServerRequestDelegate requestHandler;
		HTTPServerSettings settings;
		HTTPLogger[] loggers;
		size_t id;
	}

	private {
		TCPListener m_listener;
		VirtualHost[] m_virtualHosts;
		string m_bindAddress;
		ushort m_bindPort;
		TLSContext m_tlsContext;
		static size_t s_vhostIDCounter = 1;
	}

	@safe:

	this(string bind_address, ushort bind_port)
	{
		m_bindAddress = bind_address;
		m_bindPort = bind_port;
	}

	/** Returns the TLS context associated with the listener.

		For non-HTTPS listeners, `null` will be returned. Otherwise, if only a
		single virtual host has been added, the TLS context of that host's
		settings is returned. For multiple virtual hosts, an SNI context is
		returned, which forwards to the individual contexts based on the
		requested host name.
	*/
	@property TLSContext tlsContext() { return m_tlsContext; }

	/// The local network interface IP address associated with this listener
	@property string bindAddress() const { return m_bindAddress; }

	/// The local port associated with this listener
	@property ushort bindPort() const { return m_bindPort; }

	/// Determines if any virtual hosts have been addded
	@property bool hasVirtualHosts() const { return m_virtualHosts.length > 0; }

	/// Make m_virtualhosts visible
	@property scope VirtualHost[] virtualHosts() { return m_virtualHosts; }

	/** Adds a single virtual host.

		Note that the port and bind address defined in `settings` must match the
		ones for this listener. The `settings.host` field must be unique for
		all virtual hosts.

		Returns: Returns a unique ID for the new virtual host
	*/
	size_t addVirtualHost(HTTPServerSettings settings, HTTPServerRequestDelegate request_handler)
	{
		assert(settings.port == 0 || settings.port == m_bindPort, "Virtual host settings do not match bind port.");
		assert(settings.bindAddresses.canFind(m_bindAddress), "Virtual host settings do not match bind address.");

		VirtualHost vhost;
		vhost.id = s_vhostIDCounter++;
		vhost.settings = settings;
		vhost.requestHandler = request_handler;

		if (settings.accessLogger) vhost.loggers ~= settings.accessLogger;
		if (settings.accessLogToConsole)
			vhost.loggers ~= new HTTPConsoleLogger(settings, settings.accessLogFormat);
		if (settings.accessLogFile.length)
			vhost.loggers ~= new HTTPFileLogger(settings, settings.accessLogFormat, settings.accessLogFile);

		if (!m_virtualHosts.length) m_tlsContext = settings.tlsContext;

		enforce((m_tlsContext !is null) == (settings.tlsContext !is null),
			"Cannot mix HTTP and HTTPS virtual hosts within the same listener.");

		if (m_tlsContext) addSNIHost(settings);

		m_virtualHosts ~= vhost;

		if (settings.hostName.length) {
			auto proto = settings.tlsContext ? "https" : "http";
			auto port = settings.tlsContext && settings.port == 443 || !settings.tlsContext && settings.port == 80 ? "" : ":" ~ settings.port.to!string;
			logInfo("Added virtual host %s://%s:%s/ (%s)", proto, settings.hostName, m_bindPort, m_bindAddress);
		}

		return vhost.id;
	}

	/// Removes a previously added virtual host using its ID.
	bool removeVirtualHost(size_t id)
	{
		import std.algorithm.searching : countUntil;

		auto idx = m_virtualHosts.countUntil!(c => c.id == id);
		if (idx < 0) return false;

		auto ctx = m_virtualHosts[idx];
		m_virtualHosts = m_virtualHosts[0 .. idx] ~ m_virtualHosts[idx+1 .. $];
		return true;
	}

	void stopListening()
	{
		m_listener.stopListening();
	}

	private void addSNIHost(HTTPServerSettings settings)
	{
		if (settings.tlsContext !is m_tlsContext && m_tlsContext.kind != TLSContextKind.serverSNI) {
			logDebug("Create SNI TLS context for %s, port %s", bindAddress, bindPort);
			m_tlsContext = createTLSContext(TLSContextKind.serverSNI);
			m_tlsContext.sniCallback = &onSNI;
		}

	}

	private TLSContext onSNI(string servername)
	{
		foreach (vhost; m_virtualHosts)
			if (vhost.settings.hostName.icmp(servername) == 0) {
				logDebug("Found context for SNI host '%s'.", servername);
				return vhost.settings.tlsContext;
			}
		logDebug("No context found for SNI host '%s'.", servername);
		return null;
	}
}


/**************************************************************************************************/
/* Private types																				  */
/**************************************************************************************************/

private enum MaxHTTPHeaderLineLength = 4096;

/**************************************************************************************************/
/* Private functions																			  */
/**************************************************************************************************/

private {
	import core.sync.mutex;

	shared string s_distHost;
	shared ushort s_distPort = 11000;

	HTTPServerContext[] s_listeners;
}


private {
	HTTPContext[] s_contexts;
}

//private HTTPContext getDefaultHTTPContext(in ref NetworkAddress addr)

	//assert(false, "TODO");
//}


/**
  [private] Starts a HTTP server listening on the specified port.

  This is the same as listenHTTP() except that it does not use a VibeDist host for
  remote listening, even if specified on the command line.
*/

private HTTPListener listenHTTPPlain(HTTPServerSettings settings, HTTPServerRequestDelegate request_handler)
@safe
{
	import vibe.core.core : runWorkerTaskDist;
	import std.algorithm : canFind, find;

	static TCPListener doListen(HTTPServerContext listen_info, bool dist, bool reusePort)
	@safe {
		try {
			TCPListenOptions options = TCPListenOptions.defaults;
			if(reusePort) options |= TCPListenOptions.reusePort; else options &= ~TCPListenOptions.reusePort;
			auto ret = listenTCP(listen_info.bindPort, (TCPConnection conn) nothrow @safe {
					logInfo("ListenHTTP");
					try { handleHTTP1Connection(conn, listen_info);
					} catch (Exception e) {
						logError("HTTP connection handler has thrown: %s", e.msg);
						debug logDebug("Full error: %s", () @trusted { return e.toString().sanitize(); } ());
						try conn.close();
						catch (Exception e) logError("Failed to close connection: %s", e.msg);
					}
				}, listen_info.bindAddress, options);

			// support port 0 meaning any available port
			if (listen_info.bindPort == 0)
				listen_info.m_bindPort = ret.bindAddress.port;

			auto proto = listen_info.tlsContext ? "https" : "http";
			auto urladdr = listen_info.bindAddress;
			if (urladdr.canFind(':')) urladdr = "["~urladdr~"]";
			logInfo("Listening for requests on %s://%s:%s/", proto, urladdr, listen_info.bindPort);
			return ret;
		} catch( Exception e ) {
			logWarn("Failed to listen on %s:%s", listen_info.bindAddress, listen_info.bindPort);
			return TCPListener.init;
		}
	}

	size_t[] vid;

	// Check for every bind address/port, if a new listening socket needs to be created and
	// check for conflicting servers
	foreach (addr; settings.bindAddresses) {
		HTTPServerContext linfo;

		auto l = s_contexts.find!(l => l.bindAddress == addr && l.bindPort == settings.port);
		if (!l.empty) linfo = l.front;
		else {
			auto li = new HTTPServerContext(addr, settings.port);
			if (auto tcp_lst = doListen(li, (settings.options & HTTPServerOptionImpl.distribute) != 0, (settings.options & HTTPServerOption.reusePort) != 0)) // DMD BUG 2043
			{
				li.m_listener = tcp_lst;
				s_contexts ~= li;
				linfo = li;
			}
		}

		if (linfo) vid ~= linfo.addVirtualHost(settings, request_handler);
	}

	enforce(vid.length > 0, "Failed to listen for incoming HTTP connections on any of the supplied interfaces.");

	return HTTPListener(vid);
}

unittest{
	// testing a class that implements HTTPServerRequestHandler

	class MyReqHandler : HTTPServerRequestHandler
	{
		override void handleRequest(HTTPServerRequest req, HTTPServerResponse res)
		@safe {
			if (req.path == "/")
			res.writeBody("Hello, World! Interface");
		}
	}

	auto settings = HTTPServerSettings();
	settings.port = 8050;
	settings.bindAddresses = ["localhost"];

	MyReqHandler mrh = new MyReqHandler;

	listenHTTP!mrh(settings);
}

unittest {
	// testing HTTPS connections
	void handleRequest (HTTPServerRequest req, HTTPServerResponse res)
	@safe {
		if (req.path == "/")
		res.writeBody("Hello, World! Delegate");
	}

	auto settings = HTTPServerSettings();
	settings.port = 8070;
	settings.bindAddresses = ["localhost"];
	settings.tlsContext = createTLSContext(TLSContextKind.server);
	settings.tlsContext.useCertificateChainFile("tests/server.crt");
	settings.tlsContext.usePrivateKeyFile("tests/server.key");

	listenHTTP!handleRequest(settings);
}

//// NOTE: just a possible idea for the low level api
//struct HTTPRequestHandler {
	//void read(alias HeaderCallback, alias BodyCallback)()
	//{
		//connection.readHeaders!HeaderCallback();
		//connection.readBody!BodyCallback();
	//}

	//void write(alias HeaderCallback, alias BodyCallback)()
	//{
		//connection.writeHeader!HeaderCallback();
		//connection.writeBody!BodyCallback();
	//}
//}


struct HTTPServerRequestData {
	@disable this(this);

	@safe:

	private {
		SysTime m_timeCreated;
		HTTPServerSettings m_settings;
		ushort m_port;
		string m_peer;
	}

	protected {

		InterfaceProxy!Stream m_conn;

		/// The HTTP protocol version used for the request

		HTTPVersion httpVersion = HTTPVersion.HTTP_1_1;

		/// The HTTP _method of the request
		HTTPMethod method = HTTPMethod.GET;

		/** The request URI

			Note that the request URI usually does not include the global
			'http://server' part, but only the local path and a query string.
			A possible exception is a proxy server, which will get full URLs.
		*/
		string requestURI = "/";

		/// Compatibility alias - scheduled for deprecation
		alias requestURL = requestURI;

		/// All request _headers
		InetHeaderMap headers;

		/// The IP address of the client
		@property string peer()
		@safe nothrow {
			if (!m_peer) {
				version (Have_vibe_core) {} else scope (failure) assert(false);
				// store the IP address (IPv4 addresses forwarded over IPv6 are stored in IPv4 format)
				auto peer_address_string = this.clientAddress.toString();
				if (peer_address_string.startsWith("::ffff:") && peer_address_string[7 .. $].indexOf(':') < 0)
					m_peer = peer_address_string[7 .. $];
				else m_peer = peer_address_string;
			}
			return m_peer;
		}

		/// ditto
		NetworkAddress clientAddress;

		/// Determines if the request should be logged to the access log file.
		bool noLog;

		/// Determines if the request was issued over an TLS encrypted channel.
		bool tls;

		/* Information about the TLS certificate provided by the client.

			Remarks: This field is only set if `tls` is true, and the peer
			presented a client certificate.
		*/
		TLSCertificateInformation clientCertificate;

		/* Deprecated: The _path part of the URL.

			Note that this function contains the decoded version of the
			requested path, which can yield incorrect results if the path
			contains URL encoded path separators. Use `requestPath` instead to
			get an encoding-aware representation.
		*/
		string path() @safe {
			if (_path.isNull) {
				_path = urlDecode(requestPath.toString);
			}
			return _path.get;
		}

		private Nullable!string _path;

		//* The path part of the requested URI.
		InetPath requestPath;

		//* The user name part of the URL, if present.
		string username;

		//* The _password part of the URL, if present.
		string password;

		//* The _query string part of the URL.
		string queryString;

		/* Contains the list of _cookies that are stored on the client.

			Note that the a single cookie name may occur multiple times if multiple
			cookies have that name but different paths or domains that all match
			the request URI. By default, the first cookie will be returned, which is
			the or one of the cookies with the closest path match.
		*/
		@property ref CookieValueMap cookies() @safe {
			if (_cookies.isNull) {
				_cookies = CookieValueMap.init;
				if (auto pv = "cookie" in headers)
					parseCookies(*pv, _cookies);
			}
			return _cookies.get;
		}
		private Nullable!CookieValueMap _cookies;

		/* Contains all _form fields supplied using the _query string.

			The fields are stored in the same order as they are received.
		*/
		@property ref FormFields query() @safe {
			if (_query.isNull) {
				_query = FormFields.init;
				parseURLEncodedForm(queryString, _query);
			}

			return _query.get;
		}
		Nullable!FormFields _query;

		import vibe.utils.dictionarylist;
		/* A map of general parameters for the request.

			This map is supposed to be used by middleware functionality to store
			information for later stages. For example vibe.http.router.URLRouter uses this map
			to store the value of any named placeholders.
		*/

		import std.variant : Variant;
		/* A map of context items for the request.

			This is especially useful for passing application specific data down
			the chain of processors along with the request itself.

			For example, a generic route may be defined to check user login status,
			if the user is logged in, add a reference to user specific data to the
			context.

			This is implemented with `std.variant.Variant` to allow any type of data.
		*/
		DictionaryList!(Variant, true, 2) context;

		/* Supplies the request body as a stream.

			Note that when certain server options are set (such as
			HTTPServerOption.parseJsonBody) and a matching request was sent,
			the returned stream will be empty. If needed, remove those
			options and do your own processing of the body when launching
			the server. HTTPServerOption has a list of all options that affect
			the request body.
		*/
		InputStream bodyReader;

		/* Contains the parsed Json for a JSON request.

			A JSON request must have the Content-Type "application/json" or "application/vnd.api+json".
		*/
		@property ref Json json() @safe {
			if (_json.isNull) {
				if (icmp2(contentType, "application/json") == 0 || icmp2(contentType, "application/vnd.api+json") == 0 ) {
					auto bodyStr = bodyReader.readAllUTF8();
					if (!bodyStr.empty) _json = parseJson(bodyStr);
				} else {
					_json = Json.undefined;
				}
			}
			return _json.get;
		}

		private Nullable!Json _json;

		/* Contains the parsed parameters of a HTML POST _form request.

			The fields are stored in the same order as they are received.

			Remarks:
				A form request must either have the Content-Type
				"application/x-www-form-urlencoded" or "multipart/form-data".
		*/
		@property ref FormFields form() @safe {
			if (_form.isNull)
				parseFormAndFiles();

			return _form.get;
		}

		private Nullable!FormFields _form;

		private void parseFormAndFiles() @safe {
			_form = FormFields.init;
			assert(!!bodyReader);
			parseFormData(_form, _files, headers.get("Content-Type", ""), bodyReader, MaxHTTPHeaderLineLength);
		}

		//* Contains information about any uploaded file for a HTML _form request.
		@property ref FilePartFormFields files() @safe {
			// _form and _files are parsed in one step
			if (_form.isNull) {
				parseFormAndFiles();
				assert(!_form.isNull);
			}

			return _files;
		}

		private FilePartFormFields _files;

		/* The current Session object.

			This field is set if HTTPServerResponse.startSession() has been called
			on a previous response and if the client has sent back the matching
			cookie.

			Remarks: Requires the HTTPServerOption.parseCookies option.
		*/
		Session session;

		public string toString()
		{
			return httpMethodString(method) ~ " " ~ requestURL ~ " " ~ getHTTPVersionString(httpVersion);
		}

		/** Shortcut to the 'Host' header (always present for HTTP 1.1)
		 */
		@property string host() const { auto ph = "Host" in headers; return ph ? *ph : null; }
		/// ditto
		@property void host(string v) { headers["Host"] = v; }

		/** Returns the mime type part of the 'Content-Type' header.

		  This function gets the pure mime type (e.g. "text/plain")
		  without any supplimentary parameters such as "charset=...".
		  Use contentTypeParameters to get any parameter string or
		  headers["Content-Type"] to get the raw value.
		 */
		@property string contentType()
			const {
				auto pv = "Content-Type" in headers;
				if( !pv ) return null;
				auto idx = std.string.indexOf(*pv, ';');
				return idx >= 0 ? (*pv)[0 .. idx] : *pv;
			}
		/// ditto
		@property void contentType(string ct) { headers["Content-Type"] = ct; }

		/** Returns any supplementary parameters of the 'Content-Type' header.

		  This is a semicolon separated ist of key/value pairs. Usually, if set,
		  this contains the character set used for text based content types.
		 */
		@property string contentTypeParameters()
		const {
			auto pv = "Content-Type" in headers;
			if( !pv ) return null;
			auto idx = std.string.indexOf(*pv, ';');
			return idx >= 0 ? (*pv)[idx+1 .. $] : null;
		}

		/** Determines if the connection persists across requests.
		*/
		@property bool persistent() const
		{
			auto ph = "connection" in headers;
			switch(httpVersion) {
				case HTTPVersion.HTTP_1_0:
					if (ph && toLower(*ph) == "keep-alive") return true;
					return false;
				case HTTPVersion.HTTP_1_1:
					if (ph && toLower(*ph) != "keep-alive") return false;
					return true;
				default:
					return false;
			}
		}
	}

	package {
		//* The settings of the server serving this request.
		@property const(HTTPServerSettings) serverSettings() const @safe
		{
			return m_settings;
		}
	}

	this(SysTime time, ushort port)
	@safe {
		m_timeCreated = time.toUTC();
		m_port = port;
	}

	//* Time when this request started processing.
	@property SysTime timeCreated() const @safe { return m_timeCreated; }


	/* The full URL that corresponds to this request.

		The host URL includes the protocol, host and optionally the user
		and password that was used for this request. This field is useful to
		construct self referencing URLs.

		Note that the port is currently not set, so that this only works if
		the standard port is used.
	*/
	@property URL fullURL()
	const @safe {
		URL url;

		auto xfh = this.headers.get("X-Forwarded-Host");
		auto xfp = this.headers.get("X-Forwarded-Port");
		auto xfpr = this.headers.get("X-Forwarded-Proto");

		// Set URL host segment.
		if (xfh.length) {
			url.host = xfh;
		} else if (!this.host.empty) {
			url.host = this.host;
		} else if (!m_settings.hostName.empty) {
			url.host = m_settings.hostName;
		} else {
			url.host = m_settings.bindAddresses[0];
		}

		// Set URL schema segment.
		if (xfpr.length) {
			url.schema = xfpr;
		} else if (this.tls) {
			url.schema = "https";
		} else {
			url.schema = "http";
		}

		// Set URL port segment.
		if (xfp.length) {
			try {
				url.port = xfp.to!ushort;
			} catch (ConvException) {
				// TODO : Consider responding with a 400/etc. error from here.
				logWarn("X-Forwarded-Port header was not valid port (%s)", xfp);
			}
		} else if (!xfh) {
			if (url.schema == "https") {
				if (m_port != 443U) url.port = m_port;
			} else {
				if (m_port != 80U)	url.port = m_port;
			}
		}

		if (url.host.startsWith('[')) { // handle IPv6 address
			auto idx = url.host.indexOf(']');
			if (idx >= 0 && idx+1 < url.host.length && url.host[idx+1] == ':')
				url.host = url.host[1 .. idx];
		} else { // handle normal host names or IPv4 address
			auto idx = url.host.indexOf(':');
			if (idx >= 0) url.host = url.host[0 .. idx];
		}

		url.username = this.username;
		url.password = this.password;
		url.localURI = this.requestURI;

		return url;
	}

	/* The relative path to the root folder.

		Using this function instead of absolute URLs for embedded links can be
		useful to avoid dead link when the site is piped through a
		reverse-proxy.

		The returned string always ends with a slash.
	*/
	@property string rootDir()
	const @safe {
		import std.range.primitives : walkLength;
		auto depth = requestPath.bySegment.walkLength;
		return depth == 0 ? "./" : replicate("../", depth);
	}
}


struct HTTPServerResponseData {
	@disable this(this);
	@safe:

	private {
		InterfaceProxy!Stream m_conn;
		InterfaceProxy!ConnectionStream m_rawConnection;
		InterfaceProxy!OutputStream m_bodyWriter;
		IAllocator m_requestAlloc;
		FreeListRef!ChunkedOutputStream m_chunkedBodyWriter;
		FreeListRef!CountingOutputStream m_countingWriter;
		FreeListRef!ZlibOutputStream m_zlibOutputStream;
		HTTPServerSettings m_settings;
		Session m_session;
		bool m_headerWritten = false;
		bool m_isHeadResponse = false;
		bool m_tls;
		SysTime m_timeFinalized;
	}

	protected {
		/// The protocol version of the response - should not be changed
		HTTPVersion httpVersion = HTTPVersion.HTTP_1_1;

		/// The status code of the response, 200 by default
		int statusCode = HTTPStatus.OK;

		/** The status phrase of the response

			If no phrase is set, a default one corresponding to the status code will be used.
		*/
		string statusPhrase;

		/// The response header fields
		InetHeaderMap headers;

		/// All cookies that shall be set on the client for this request
		Cookie[string] cookies;
		/** Shortcut to the "Content-Type" header
		 */
		@property string contentType() const { auto pct = "Content-Type" in headers; return pct ? *pct : "application/octet-stream"; }
		/// ditto
		@property void contentType(string ct) { headers["Content-Type"] = ct; }

		static if (!is(Stream == InterfaceProxy!Stream)) {
			this(Stream conn, ConnectionStream raw_connection, HTTPServerSettings settings, IAllocator req_alloc)
				@safe {
					this(InterfaceProxy!Stream(conn), InterfaceProxy!ConnectionStream(raw_connection), settings, req_alloc);
				}
		}

		this(InterfaceProxy!Stream conn, InterfaceProxy!ConnectionStream raw_connection, HTTPServerSettings settings, IAllocator req_alloc)
			@safe {
				m_conn = conn;
				m_rawConnection = raw_connection;
				m_countingWriter = createCountingOutputStreamFL(conn);
				m_settings = settings;
				m_requestAlloc = req_alloc;
			}

		/** Returns the time at which the request was finalized.

		  Note that this field will only be set after `finalize` has been called.
		 */
		@property SysTime timeFinalized() const @safe { return m_timeFinalized; }

		/** Determines if the HTTP header has already been written.
		 */
		@property bool headerWritten() const @safe { return m_headerWritten; }

		/** Determines if the response does not need a body.
		 */
		bool isHeadResponse() const @safe { return m_isHeadResponse; }

		/** Determines if the response is sent over an encrypted connection.
		 */
		bool tls() const @safe { return m_tls; }

		/** Writes the entire response body at once.

			Params:
				data = The data to write as the body contents
				status = Optional response status code to set
				content_tyoe = Optional content type to apply to the response.
					If no content type is given and no "Content-Type" header is
					set in the response, this will default to
					`"application/octet-stream"`.

			See_Also: `HTTPStatusCode`
		 */
		void writeBody(in ubyte[] data, string content_type = null)
			@safe {
				if (content_type.length) headers["Content-Type"] = content_type;
				else if ("Content-Type" !in headers) headers["Content-Type"] = "application/octet-stream";
				ulong length = data.length;
				headers["Content-Length"] = formatAlloc(m_requestAlloc, "%d", length);
				headers["Content-Length"] = format("%d", length);
				bodyWriter.write(data);
			}
		/// ditto
		void writeBody(in ubyte[] data, int status, string content_type = null)
			@safe {
				statusCode = status;
				writeBody(data, content_type);
			}
		/// ditto
		void writeBody(scope InputStream data, string content_type = null)
			@safe {
				if (content_type.length) headers["Content-Type"] = content_type;
				else if ("Content-Type" !in headers) headers["Content-Type"] = "application/octet-stream";
				data.pipe(bodyWriter);
			}

		/** Writes the entire response body as a single string.

				Params:
					data = The string to write as the body contents
					status = Optional response status code to set
					content_type = Optional content type to apply to the response.
						If no content type is given and no "Content-Type" header is
						set in the response, this will default to
						`"text/plain; charset=UTF-8"`.

				See_Also: `HTTPStatusCode`
		 */
		/// ditto
		void writeBody(string data, string content_type = null)
			@safe {
				if (!content_type.length && "Content-Type" !in headers)
					content_type = "text/plain; charset=UTF-8";
				writeBody(cast(const(ubyte)[])data, content_type);
			}
		/// ditto
		void writeBody(string data, int status, string content_type = null)
			@safe {
				statusCode = status;
				writeBody(data, content_type);
			}

		/** Writes the whole response body at once, without doing any further encoding.

			  The caller has to make sure that the appropriate headers are set correctly
			  (i.e. Content-Type and Content-Encoding).

			  Note that the version taking a RandomAccessStream may perform additional
			  optimizations such as sending a file directly from the disk to the
			  network card using a DMA transfer.

		 */
		void writeRawBody(RandomAccessStream)(RandomAccessStream stream) @safe
			if (isRandomAccessStream!RandomAccessStream)
			{
				assert(!m_headerWritten, "A body was already written!");
				writeHeader();
				if (m_isHeadResponse) return;

				auto bytes = stream.size - stream.tell();
				stream.pipe(m_conn);
				m_countingWriter.increment(bytes);
			}
		/// ditto
		void writeRawBody(InputStream)(InputStream stream, size_t num_bytes = 0) @safe
			if (isInputStream!InputStream && !isRandomAccessStream!InputStream)
			{
				assert(!m_headerWritten, "A body was already written!");
				writeHeader();
				if (m_isHeadResponse) return;

				if (num_bytes > 0) {
					stream.pipe(m_conn, num_bytes);
					m_countingWriter.increment(num_bytes);
				} else stream.pipe(m_countingWriter, num_bytes);
			}
		/// ditto
		void writeRawBody(RandomAccessStream)(RandomAccessStream stream, int status) @safe
			if (isRandomAccessStream!RandomAccessStream)
			{
				statusCode = status;
				writeRawBody(stream);
			}
		/// ditto
		void writeRawBody(InputStream)(InputStream stream, int status, size_t num_bytes = 0) @safe
			if (isInputStream!InputStream && !isRandomAccessStream!InputStream)
			{
				statusCode = status;
				writeRawBody(stream, num_bytes);
			}


		/// Writes a JSON message with the specified status
		void writeJsonBody(T)(T data, int status, bool allow_chunked = false)
		{
			statusCode = status;
			writeJsonBody(data, allow_chunked);
		}
		/// ditto
		void writeJsonBody(T)(T data, int status, string content_type, bool allow_chunked = false)
		{
			statusCode = status;
			writeJsonBody(data, content_type, allow_chunked);
		}

		/// ditto
		void writeJsonBody(T)(T data, string content_type, bool allow_chunked = false)
		{
			headers["Content-Type"] = content_type;
			writeJsonBody(data, allow_chunked);
		}
		/// ditto
		void writeJsonBody(T)(T data, bool allow_chunked = false)
		{
			doWriteJsonBody!(T, false)(data, allow_chunked);
		}
		/// ditto
		void writePrettyJsonBody(T)(T data, bool allow_chunked = false)
		{
			doWriteJsonBody!(T, true)(data, allow_chunked);
		}

		private void doWriteJsonBody(T, bool PRETTY)(T data, bool allow_chunked = false)
		{
			import std.traits;
			import vibe.stream.wrapper;

			static if (!is(T == Json) && is(typeof(data.data())) && isArray!(typeof(data.data()))) {
				static assert(!is(T == Appender!(typeof(data.data()))), "Passed an Appender!T to writeJsonBody - this is most probably not doing what's indended.");
			}

			if ("Content-Type" !in headers)
				headers["Content-Type"] = "application/json; charset=UTF-8";


			// set an explicit content-length field if chunked encoding is not allowed
			if (!allow_chunked) {
				import vibe.internal.rangeutil;
				long length = 0;
				auto counter = RangeCounter(() @trusted { return &length; } ());
				static if (PRETTY) serializeToPrettyJson(counter, data);
				else serializeToJson(counter, data);
				headers["Content-Length"] = formatAlloc(m_requestAlloc, "%d", length);
			}

			auto rng = streamOutputRange!1024(bodyWriter);
			static if (PRETTY) serializeToPrettyJson(() @trusted { return &rng; } (), data);
			else serializeToJson(() @trusted { return &rng; } (), data);
		}

		/**
		 * Writes the response with no body.
		 *
		 * This method should be used in situations where no body is
		 * requested, such as a HEAD request. For an empty body, just use writeBody,
		 * as this method causes problems with some keep-alive connections.
		 */
		void writeVoidBody()
			@safe {
				if (!m_isHeadResponse) {
					assert("Content-Length" !in headers);
					assert("Transfer-Encoding" !in headers);
				}
				assert(!headerWritten);
				writeHeader();
				m_conn.flush();
			}

		/** A stream for writing the body of the HTTP response.

			  Note that after 'bodyWriter' has been accessed for the first time, it
			  is not allowed to change any header or the status code of the response.
		 */
		@property InterfaceProxy!OutputStream bodyWriter()
			@safe {
				assert(!!m_conn);
				if (m_bodyWriter) return m_bodyWriter;

				assert(!m_headerWritten, "A void body was already written!");

				if (m_isHeadResponse) {
					// for HEAD requests, we define a NullOutputWriter for convenience
					// - no body will be written. However, the request handler should call writeVoidBody()
					// and skip writing of the body in this case.
					if ("Content-Length" !in headers)
						headers["Transfer-Encoding"] = "chunked";
					writeHeader();
					m_bodyWriter = nullSink;
					return m_bodyWriter;
				}

				if ("Content-Encoding" in headers && "Content-Length" in headers) {
					// we do not known how large the compressed body will be in advance
					// so remove the content-length and use chunked transfer
					headers.remove("Content-Length");
				}

				if (auto pcl = "Content-Length" in headers) {
					writeHeader();
					m_countingWriter.writeLimit = (*pcl).to!ulong;
					m_bodyWriter = m_countingWriter;
				} else if (httpVersion <= HTTPVersion.HTTP_1_0) {
					if ("Connection" in headers)
						headers.remove("Connection"); // default to "close"
					writeHeader();
					m_bodyWriter = m_conn;
				} else {
					headers["Transfer-Encoding"] = "chunked";
					writeHeader();
					m_chunkedBodyWriter = createChunkedOutputStreamFL(m_countingWriter);
					m_bodyWriter = m_chunkedBodyWriter;
				}

				if (auto pce = "Content-Encoding" in headers) {
					if (icmp2(*pce, "gzip") == 0) {
						m_zlibOutputStream = createGzipOutputStreamFL(m_bodyWriter);
						m_bodyWriter = m_zlibOutputStream;
					} else if (icmp2(*pce, "deflate") == 0) {
						m_zlibOutputStream = createDeflateOutputStreamFL(m_bodyWriter);
						m_bodyWriter = m_zlibOutputStream;
					} else {
						logWarn("Unsupported Content-Encoding set in response: '"~*pce~"'");
					}
				}

				return m_bodyWriter;
			}

		/**
		  * Used to change the bodyWriter during a HTTP/2 upgrade
		  */
		@property void bodyWriter(T)(ref T writer) @safe
		{
			assert(!m_bodyWriter && !headerWritten, "Unable to set bodyWriter");
			// write the current set headers before initiating the bodyWriter
			writeHeader(writer);
			static if(!is(T == InterfaceProxy!OutputStream)) {
				InterfaceProxy!OutputStream bwriter = writer;
				m_bodyWriter = bwriter;
			} else {
				m_bodyWriter = writer;
			}
		}

		/** Sends a redirect request to the client.

				Params:
					url = The URL to redirect to
					status = The HTTP redirect status (3xx) to send - by default this is $(D HTTPStatus.found)
		 */
		void redirect(string url, int status = HTTPStatus.Found)
			@safe {
				// Disallow any characters that may influence the header parsing
				enforce(!url.representation.canFind!(ch => ch < 0x20),
						"Control character in redirection URL.");

				statusCode = status;
				headers["Location"] = url;
				writeBody("redirecting...");
			}
		/// ditto
		void redirect(URL url, int status = HTTPStatus.Found)
			@safe {
				redirect(url.toString(), status);
			}

		///
		@safe unittest {
			import vibe.http.router;

			void request_handler(HTTPServerRequest req, HTTPServerResponse res)
			{
				res.redirect("http://example.org/some_other_url");
			}

			void test()
			{
				auto router = new URLRouter;
				router.get("/old_url", &request_handler);
				HTTPServerSettings settings;
				listenHTTP!router(settings);
			}
		}


		/** Special method sending a SWITCHING_PROTOCOLS response to the client.

				Notice: For the overload that returns a `ConnectionStream`, it must be
					ensured that the returned instance doesn't outlive the request
					handler callback.

				Notice: The overload which accepts a connection_handler alias is used for
					HTTP/1 to HTTP/2 switching in cleartext HTTP

				Params:
					protocol = The protocol set in the "Upgrade" header of the response.
					Use an empty string to skip setting this field.
		 */
		ConnectionStream switchProtocol(string protocol)
			@safe {
				statusCode = HTTPStatus.SwitchingProtocols;
				if (protocol.length) headers["Upgrade"] = protocol;
				writeVoidBody();
				return createConnectionProxyStream(m_conn, m_rawConnection);
			}

		/// ditto
		void switchProtocol(string protocol, scope void delegate(scope ConnectionStream) @safe del)
			@safe {
				statusCode = HTTPStatus.SwitchingProtocols;
				if (protocol.length) headers["Upgrade"] = protocol;
				writeVoidBody();
				() @trusted {
					auto conn = createConnectionProxyStreamFL(m_conn, m_rawConnection);
					del(conn);
				} ();
				finalize();
				if (m_rawConnection && m_rawConnection.connected)
					m_rawConnection.close(); // connection not reusable after a protocol upgrade
			}

		package void switchToHTTP2(HANDLER)(HANDLER handler, HTTP2ServerContext context)
			@safe {
				logInfo("sending SWITCHING_PROTOCOL response");

				statusCode = HTTPStatus.switchingProtocols;
				headers["Upgrade"] = "h2c";

				writeVoidBody();

				// TODO improve handler (handleHTTP2Connection) connection management
				auto tcp_conn = m_rawConnection.extract!TCPConnection;
				handler(tcp_conn, tcp_conn, context);

				finalize();
				// close the existing connection
				if (m_rawConnection && m_rawConnection.connected)
				m_rawConnection.close(); // connection not reusable after a protocol upgrade
			}

		// send a badRequest error response and close the connection
		package void sendBadRequest() @safe
		{
			statusCode = HTTPStatus.badRequest;

			writeVoidBody();

			finalize();
			if (m_rawConnection && m_rawConnection.connected)
				m_rawConnection.close(); // connection not reusable after a protocol upgrade
		}


		/** Special method for handling CONNECT proxy tunnel

				Notice: For the overload that returns a `ConnectionStream`, it must be
					ensured that the returned instance doesn't outlive the request
					handler callback.
		 */
		ConnectionStream connectProxy()
			@safe {
				return createConnectionProxyStream(m_conn, m_rawConnection);
			}
		/// ditto
		void connectProxy(scope void delegate(scope ConnectionStream) @safe del)
			@safe {
				() @trusted {
					auto conn = createConnectionProxyStreamFL(m_conn, m_rawConnection);
					del(conn);
				} ();
				finalize();
				m_rawConnection.close(); // connection not reusable after a protocol upgrade
			}

		/** Sets the specified cookie value.

				Params:
					name = Name of the cookie
					value = New cookie value - pass null to clear the cookie
					path = Path (as seen by the client) of the directory tree in which the cookie is visible
		 */
		Cookie setCookie(string name, string value, string path = "/", Cookie.Encoding encoding = Cookie.Encoding.url)
			@safe {
				auto cookie = new Cookie();
				cookie.path = path;
				cookie.setValue(value, encoding);
				if (value is null) {
					cookie.maxAge = 0;
					cookie.expires = "Thu, 01 Jan 1970 00:00:00 GMT";
				}
				cookies[name] = cookie;
				return cookie;
			}

		/**
		  Initiates a new session.

		  The session is stored in the SessionStore that was specified when
		  creating the server. Depending on this, the session can be persistent
		  or temporary and specific to this server instance.
		 */
		Session startSession(string path = "/", SessionOption options = SessionOption.httpOnly)
			@safe {
				assert(m_settings.sessionStore, "no session store set");
				assert(!m_session, "Try to start a session, but already started one.");

				bool secure;
				if (options & SessionOption.secure) secure = true;
				else if (options & SessionOption.noSecure) secure = false;
				else secure = this.tls;

				m_session = m_settings.sessionStore.create();
				m_session.set("$sessionCookiePath", path);
				m_session.set("$sessionCookieSecure", secure);
				auto cookie = setCookie(m_settings.sessionIdCookie, m_session.id, path);
				cookie.secure = secure;
				cookie.httpOnly = (options & SessionOption.httpOnly) != 0;
				return m_session;
			}

		/**
		  Terminates the current session (if any).
		 */
		void terminateSession()
			@safe {
				if (!m_session) return;
				auto cookie = setCookie(m_settings.sessionIdCookie, null, m_session.get!string("$sessionCookiePath"));
				cookie.secure = m_session.get!bool("$sessionCookieSecure");
				m_session.destroy();
				m_session = Session.init;
			}

		@property ulong bytesWritten() @safe const { return m_countingWriter.bytesWritten; }

		/**
		  Waits until either the connection closes, data arrives, or until the
		  given timeout is reached.

				Returns:
					$(D true) if the connection was closed and $(D false) if either the
					timeout was reached, or if data has arrived for consumption.

					See_Also: `connected`
		 */
		bool waitForConnectionClose(Duration timeout = Duration.max)
			@safe {
				if (!m_rawConnection || !m_rawConnection.connected) return true;
				m_rawConnection.waitForData(timeout);
				return !m_rawConnection.connected;
			}

		/**
		  Determines if the underlying connection is still alive.

		  Returns $(D true) if the remote peer is still connected and $(D false)
		  if the remote peer closed the connection.

			See_Also: `waitForConnectionClose`
		 */
		@property bool connected()
			@safe const {
				if (!m_rawConnection) return false;
				return m_rawConnection.connected;
			}

		/**
		  Finalizes the response. This is usually called automatically by the server.

		  This method can be called manually after writing the response to force
		  all network traffic associated with the current request to be finalized.
		  After the call returns, the `timeFinalized` property will be set.
		 */
		void finalize()
			@safe {
				if (m_zlibOutputStream) {
					m_zlibOutputStream.finalize();
					m_zlibOutputStream.destroy();
				}
				if (m_chunkedBodyWriter) {
					m_chunkedBodyWriter.finalize();
					m_chunkedBodyWriter.destroy();
				}

				// ignore exceptions caused by an already closed connection - the client
				// may have closed the connection already and this doesn't usually indicate
				// a problem.
				if (m_rawConnection && m_rawConnection.connected) {
					try if (m_conn) m_conn.flush();
					catch (Exception e) logDebug("Failed to flush connection after finishing HTTP response: %s", e.msg);
					if (!isHeadResponse && bytesWritten < headers.get("Content-Length", "0").to!long) {
						logDebug("HTTP response only written partially before finalization. Terminating connection.");
						m_rawConnection.close();
					}
					m_rawConnection = InterfaceProxy!ConnectionStream.init;
				}

				if (m_conn) {
					m_conn = InterfaceProxy!Stream.init;
					m_timeFinalized = Clock.currTime(UTC());
				}
			}

	}

	private void writeHeader()
	@safe {
		writeHeader(m_conn);
	}

	// accept a destination stream
	private void writeHeader(Stream)(Stream conn) @safe
		if(isStream!Stream || isOutputStream!Stream)
	{
			import vibe.stream.wrapper;

			assert(!m_bodyWriter && !m_headerWritten, "Try to write header after body has already begun.");
			m_headerWritten = true;
			auto dst = streamOutputRange!1024(conn);

			void writeLine(T...)(string fmt, T args)
				@safe {
					formattedWrite(() @trusted { return &dst; } (), fmt, args);
					dst.put("\r\n");
					logTrace(fmt, args);
				}

			logTrace("---------------------");
			logTrace("HTTP server response:");
			logTrace("---------------------");

			// write the status line
			writeLine("%s %d %s",
					getHTTPVersionString(this.httpVersion),
					this.statusCode,
					this.statusPhrase.length ? this.statusPhrase : httpStatusText(this.statusCode));

			// write all normal headers
			foreach (k, v; this.headers) {
				dst.put(k);
				dst.put(": ");
				dst.put(v);
				dst.put("\r\n");
				logTrace("%s: %s", k, v);
			}

			logTrace("---------------------");

			// write cookies
			foreach (n, cookie; this.cookies) {
				dst.put("Set-Cookie: ");
				cookie.writeString(() @trusted { return &dst; } (), n);
				dst.put("\r\n");
			}

			// finalize response header
			dst.put("\r\n");
		}

	public string toString()
	{
		auto app = appender!string();
		formattedWrite(app, "%s %d %s", getHTTPVersionString(this.httpVersion), this.statusCode, this.statusPhrase);
		return app.data;
	}
}


private void parseCookies(string str, ref CookieValueMap cookies)
@safe {
	import std.encoding : sanitize;
	import std.array : split;
	import std.string : strip;
	import std.algorithm.iteration : map, filter, each;
	import vibe.http.common : Cookie;
	() @trusted { return str.sanitize; } ()
		.split(";")
		.map!(kv => kv.strip.split("="))
		.filter!(kv => kv.length == 2) //ignore illegal cookies
		.each!(kv => cookies.add(kv[0], kv[1], Cookie.Encoding.raw) );
}

unittest
{
	  auto cvm = CookieValueMap();
	  parseCookies("foo=bar;; baz=zinga; öö=üü	 ;	 møøse=was=sacked;	onlyval1; =onlyval2; onlykey=", cvm);
	  assert(cvm["foo"] == "bar");
	  assert(cvm["baz"] == "zinga");
	  assert(cvm["öö"] == "üü");
	  assert( "møøse" ! in cvm); //illegal cookie gets ignored
	  assert( "onlyval1" ! in cvm); //illegal cookie gets ignored
	  assert(cvm["onlykey"] == "");
	  assert(cvm[""] == "onlyval2");
	  assert(cvm.length() == 5);
	  cvm = CookieValueMap();
	  parseCookies("", cvm);
	  assert(cvm.length() == 0);
	  cvm = CookieValueMap();
	  parseCookies(";;=", cvm);
	  assert(cvm.length() == 1);
	  assert(cvm[""] == "");
}

void parseHTTP2RequestHeader(R)(ref R headers, ref HTTPServerRequest reqStruct) @safe
{
	import std.algorithm.searching : find, startsWith;
	import std.algorithm.iteration : filter;
	auto req = reqStruct.m_data;

	//Method
	req.method = cast(HTTPMethod)headers.find!((h,m) => h.name == m)(":method")[0].value;

	//Host
	req.host = cast(string)headers.find!((h,m) => h.name == m)(":authority")[0].value;

	//URI
	req.requestURI = req.host;

	//HTTP version
	req.httpVersion = HTTPVersion.HTTP_2;

	//headers
	foreach(h; headers.filter!(f => !f.name.startsWith(":"))) {
		req.headers[h.name] = cast(string)h.value;
	}
}

void parseRequestHeader(InputStream)(HTTPServerRequest reqStruct, InputStream http_stream, IAllocator alloc, ulong max_header_size)
	if (isInputStream!InputStream)
{
	auto stream = FreeListRef!LimitedHTTPInputStream(http_stream, max_header_size);
	auto req = reqStruct.m_data;

	logTrace("HTTP server reading status line");
	auto reqln = () @trusted { return cast(string)stream.readLine(MaxHTTPHeaderLineLength, "\r\n", alloc); }();

	logTrace("--------------------");
	logTrace("HTTP server request:");
	logTrace("--------------------");
	logTrace("%s", reqln);

	//Method
	auto pos = reqln.indexOf(' ');
	enforceBadRequest(pos >= 0, "invalid request method");

	req.method = httpMethodFromString(reqln[0 .. pos]);
	reqln = reqln[pos+1 .. $];
	//Path
	pos = reqln.indexOf(' ');
	enforceBadRequest(pos >= 0, "invalid request path");

	req.requestURI = reqln[0 .. pos];
	reqln = reqln[pos+1 .. $];

	req.httpVersion = parseHTTPVersion(reqln);

	//headers
	parseRFC5322Header(stream, req.headers, MaxHTTPHeaderLineLength, alloc, false);

	foreach (k, v; req.headers)
		logTrace("%s: %s", k, v);
	logTrace("--------------------");
}

string formatRFC822DateAlloc(IAllocator alloc, SysTime time)
@safe {
	auto app = AllocAppender!string(alloc);
	writeRFC822DateTimeString(app, time);
	return () @trusted { return app.data; } ();
}

version (VibeDebugCatchAll) alias UncaughtException = Throwable;
else alias UncaughtException = Exception;
