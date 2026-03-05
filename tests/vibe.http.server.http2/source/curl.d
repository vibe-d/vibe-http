module curl;

import std.conv : to;
import std.format : format;
import std.string : strip;

string urlFor(ushort port, string path)
{
	return format("http://127.0.0.1:%d%s", port, path);
}

/// Run curl with --http2-prior-knowledge and return the response body.
/// Retries on connection failure or empty response to handle server startup.
string curlH2(ushort port, string path, string[] extraArgs = [])
{
	import std.process : execute;
	import core.thread : Thread;
	import core.time : msecs;

	auto args = ["curl", "-s", "--max-time", "5", "--http2-prior-knowledge"]
		~ extraArgs ~ [urlFor(port, path)];

	foreach (attempt; 0 .. 10) {
		auto r = execute(args);
		if ((r.status == 0 || r.status == 16) && r.output.length > 0)
			return r.output;
		Thread.sleep(200.msecs);
	}
	auto r = execute(args);
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

	auto args = ["curl", "-s", "--max-time", "5", "--http2-prior-knowledge",
		"-o", "/dev/null", "-w", "%{http_code}"]
		~ extraArgs ~ [urlFor(port, path)];

	foreach (attempt; 0 .. 10) {
		auto r = execute(args);
		auto status = r.output.strip;
		if (status != "000")
			return status;
		Thread.sleep(200.msecs);
	}
	return execute(args).output.strip;
}
