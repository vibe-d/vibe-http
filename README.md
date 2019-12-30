[![vibe.d](http://vibed.org/images/logo-and-title.png)](http://vibed.org)

vibe.d is a high-performance asynchronous I/O, concurrency and web application
toolkit written in D. This repository contains the upcoming HTTP module that
is going to replace the existing HTTP/1.1 implementation.

[![Posix Build Status](https://travis-ci.org/vibe-d/vibe-http.svg?branch=master)](https://travis-ci.org/vibe-d/vibe-http)
[![Windows Build status](https://ci.appveyor.com/api/projects/status/9r1p1avpl75nb73e?svg=true)](https://ci.appveyor.com/project/s-ludwig/vibe-http/branch/master)


Experimental status
===================

This library is a partial rewrite of the original `vibe-d:http` package and should
be considered experimental. Do not use it in production, yet.

- It may still receive breaking changes
- The code in general should not be considered ready for production
- It currently lacks some features, such as the HTTP client implementation
- The HTTP/2 server still needs extensive testing
