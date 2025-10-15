1.3.2 - 2025-10-15
==================

- Added `HTTPClientRequest.setCookie` (by Denis Feklushkin aka denizzzka) - [pull #64][issue64]
- Fixed a HTTP/1 request parsing logic issue that could enable request smuggling or response splitting attacks - [pull #66][issue66]
- Fixed a possible null pointer dereference when attempting to send on a closed WebSocket (by Alex Burton aka Alexibu) - [pull #63][issue63]

[issue63]: https://github.com/vibe-d/vibe-http/issues/63
[issue64]: https://github.com/vibe-d/vibe-http/issues/64
[issue66]: https://github.com/vibe-d/vibe-http/issues/66


1.3.1 - 2025-08-06
==================

- Improved compile time - [pull #61][issue61]

[issue61]: https://github.com/vibe-d/vibe-http/issues/61


1.3.0 - 2025-07-21
==================

- Added `webSocketPayloadMaxLength` and `webSocketFragmentSize` fields to `HTTP(Client/Server)Settings` (by Alex Burton aka Alexibu) - [pull #57][issue57]
- Fixed an issue with querying the peer address of a server request after connection failures - [pull #56][issue56]
- Fixed parsing cookies with values containing `=` (by IchorDev) - [pull #60][issue60]

[issue56]: https://github.com/vibe-d/vibe-http/issues/56
[issue57]: https://github.com/vibe-d/vibe-http/issues/57
[issue60]: https://github.com/vibe-d/vibe-http/issues/60


1.2.2 - 2025-03-19
==================

- Fixes a reference counted stream being leaked to the GC after a client request - [pull #55][issue55]

[issue52]: https://github.com/vibe-d/vibe-http/issues/55


1.2.1 - 2024-12-25
==================

- Fixes compile errors when compiling `vibe-stream:tls` in the "notls" configuration - [pull #52][issue52]

[issue52]: https://github.com/vibe-d/vibe-http/issues/52


1.2.0 - 2024-12-18
==================

- Integrates **experimental** HTTP/2 server support - use `HTTPServerOption.enableHTTP2` to enable - [pull #37][issue37], [pull #42][issue42]
- `WebSocket.request` is now non-`const` to enable accessing lazy properties (by Alexibu) - [pull #41][issue41]
- Fixed `HTTPListener.stopListening` when multiple listeners are registered - [pull #44][issue44]
- Added `Cookie.SameSite.none` (by Denis Feklushkin aka Denizzzka) - [pull #45][issue45]
- Added an `HTTPServerResponse.writeBody` overload taking an input stream and status code - [pull #48][issue48]
- Fixed `WebSocket` connection close after keep-alive failure (by Alexibu) - [pull #50][issue50]
- `URLRouter` now uses MurmurHash instead of MD5 to speed up match tree generation - [pull #51][issue51]

[issue37]: https://github.com/vibe-d/vibe-http/issues/37
[issue41]: https://github.com/vibe-d/vibe-http/issues/41
[issue42]: https://github.com/vibe-d/vibe-http/issues/42
[issue44]: https://github.com/vibe-d/vibe-http/issues/44
[issue45]: https://github.com/vibe-d/vibe-http/issues/45
[issue48]: https://github.com/vibe-d/vibe-http/issues/48
[issue50]: https://github.com/vibe-d/vibe-http/issues/50
[issue51]: https://github.com/vibe-d/vibe-http/issues/51


1.1.1 - 2024-07-12
==================

- The client implementation now also uses `TCP_NODELAY` - [pull #40][issue40]

[issue40]: https://github.com/vibe-d/vibe-http/issues/40


1.1.0 - 2024-04-26
==================

- Fixed the proxy code to properly forward multiple headers with the same name (by Alexibu) - [pull #30][issue30]
- `URLRouter` now properly handles URL encoded path segments, both at registration and at match time (by Vijay Nayar) - [pull #35][issue35]

[issue30]: https://github.com/vibe-d/vibe-http/issues/30
[issue35]: https://github.com/vibe-d/vibe-http/issues/35


1.0.0 - 2024-02-17
==================

This is the first stable release, based on the code base in the vibe.d main
repository, at this point in time. Directly after this, vibe.d 0.10.0 got
released, in turn removing its copy of the HTTP code.
