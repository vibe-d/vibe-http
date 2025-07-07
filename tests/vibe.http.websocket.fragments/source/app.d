import vibe.core.core;
import vibe.core.log;
import vibe.inet.url;
import vibe.http.server;
import vibe.http.websockets;
import vibe.http.client;

shared static this()
{
	//test fragments
	auto settings = new HTTPServerSettings;
	settings.port = 0;
	settings.bindAddresses = ["127.0.0.1"];
	settings.webSocketPayloadMaxLength = 10;
	settings.webSocketFragmentSize = 4;
	immutable serverAddr = listenHTTP(settings, handleWebSockets((scope ws) {
		assert(ws.connected);
		assert(ws.receiveText() == "12");
		ws.send("ok");
		assert(ws.receiveText() == "1234");
		ws.send("ok");
		assert(ws.receiveText() == "123456");
		ws.send("ok");
		assert(ws.receiveText() == "12345678");
		ws.send("ok");
		assert(ws.receiveText() == "123456789");
		ws.send("ok");
		try{
			ws.receiveText();	//at this point the connection should close
			assert(false);
		}catch(Exception e)
		{
		}
		ws.close();
	})).bindAddresses[0];

	runTask({
		scope(exit) exitEventLoop(true);
		auto settings = new HTTPClientSettings;
		settings.webSocketFragmentSize = 4;
		try connectWebSocket(URL("http://" ~ serverAddr.toString), (scope ws) {
			assert(ws.connected);
			ws.send("12");	//single fragment
			assert(ws.receiveText() == "ok");
			ws.send("1234"); //single fragment
			assert(ws.receiveText() == "ok");
			ws.send("123456"); //two fragment
			assert(ws.receiveText() == "ok");
			ws.send("12345678"); //two fragment
			assert(ws.receiveText() == "ok");
			ws.send("123456789"); //three fragment
			assert(ws.receiveText() == "ok");
			ws.send("123456780901"); //three fragment - exeeds payload max length
			assert(!ws.waitForData);
			ws.close();
			logInfo("WebSocket fragment test successful");
		},settings);
		catch (Exception e) assert(false, e.msg);
	});
}
