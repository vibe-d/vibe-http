module curl;

import std.conv : to;
import std.format : format;
import std.string : strip;
import vibe.core.log;

string urlFor(ushort port, string path)
{
	return format("http://127.0.0.1:%d%s", port, path);
}

/// Returns true if the installed curl actually supports --http2-prior-knowledge (h2c).
/// Checks both the help text and a real invocation, since Windows curl may list
/// the flag in --help but lack nghttp2 in libcurl.
bool curlSupportsH2c()
{
	import std.process : execute;
	import std.algorithm.searching : canFind;

	auto r = execute(["curl", "--help", "all"]);
	if (r.status != 0 || !r.output.canFind("--http2-prior-knowledge"))
		return false;

	// Verify libcurl actually supports it (Windows curl may lack nghttp2)
	auto test = execute(["curl", "-s", "--http2-prior-knowledge", "--max-time", "1", "http://127.0.0.1:1"]);
	// Exit code 2 = "option not supported by libcurl", 7 = connection refused (expected)
	return test.status != 2;
}

/// Run curl with --http2-prior-knowledge and return the response body.
/// Retries on connection failure or empty response to handle server startup.
string curlH2(ushort port, string path, string[] extraArgs = [])
{
	import std.process : execute;
	import core.thread : Thread;
	import core.time : msecs;

	auto url = urlFor(port, path);
	auto args = ["curl", "-s", "--max-time", "5", "--http2-prior-knowledge"]
		~ extraArgs ~ [url];
	auto verboseArgs = ["curl", "-v", "--stderr", "-", "--max-time", "5", "--http2-prior-knowledge"]
		~ extraArgs ~ [url];

	logInfo("[curl] GET %s (body mode)", url);

	foreach (attempt; 0 .. 20) {
		auto r = execute(args);
		if ((r.status == 0 || r.status == 16) && r.output.length > 0) {
			logInfo("[curl] attempt %d: status=%d, body=%d bytes", attempt + 1, r.status, r.output.length);
			return r.output;
		}
		// On first and last failure, run verbose to capture the HTTP/2 error details
		if (attempt == 0 || attempt == 19) {
			auto vr = execute(verboseArgs);
			auto snippet = vr.output.length > 800 ? vr.output[0..800] ~ "..." : vr.output;
			logInfo("[curl] attempt %d (verbose): status=%d, output:\n%s", attempt + 1, vr.status, snippet);
		} else {
			logInfo("[curl] attempt %d: status=%d, body=%d bytes, retrying...",
				attempt + 1, r.status, r.output.length);
		}
		Thread.sleep(200.msecs);
	}
	auto r = execute(args);
	logError("[curl] all retries exhausted: status=%d, body=%d bytes, output: %s",
		r.status, r.output.length, r.output.length > 200 ? r.output[0..200] ~ "..." : r.output);
	assert(r.status == 0 || r.status == 16,
		"curl failed with status " ~ r.status.to!string ~ ", output: " ~ r.output);
	return r.output;
}

/// Run curl and return just the HTTP status code.
/// Retries on "000" (connection failed) to handle server startup.
string curlH2Status(ushort port, string path, string[] extraArgs = [])
{
	import std.process : execute;
	import core.thread : Thread;
	import core.time : msecs;

	auto url = urlFor(port, path);
	auto args = ["curl", "-s", "--max-time", "5", "--http2-prior-knowledge",
		"-o", "/dev/null", "-w", "%{http_code}"]
		~ extraArgs ~ [url];

	logInfo("[curl] GET %s (status mode)", url);

	foreach (attempt; 0 .. 20) {
		auto r = execute(args);
		auto status = r.output.strip;
		if (status != "000") {
			logInfo("[curl] attempt %d: http_code=%s", attempt + 1, status);
			return status;
		}
		logInfo("[curl] attempt %d: http_code=000 (connection failed), retrying...", attempt + 1);
		Thread.sleep(200.msecs);
	}
	auto result = execute(args).output.strip;
	logError("[curl] all retries exhausted: http_code=%s", result);
	return result;
}
