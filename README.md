# RSSLater

Turn your "I want to read this later" items into an RSS feed!

## Installation

Assuming you have [Go](https://go.dev/dl/) installed, run this:

```
go install -v code.nkcmr.net/rsslater@latest
```

## Getting Started

First, let's get it running.

### Running

Once installed, running is designed to be as simple as possible without much configuration:

```
rsslater --origin https://myrsslater-service.example.com --auto-cert
```

The `--auto-cert` option will try to use LetsEncrypt to get TLS setup for your server, but it requires the origin to be publicly reachable.

There are enough other options to get the origin to actually be reachable by some other means; a few options are below.

### Login Setup

Once the server is running, you'll need to initialize the login by adding a Webauthn Security Key (YubiKey, iPhone, Android, etc...). This is why HTTPS is required since Webauthn only works on secure pages.

### Bookmarklet

Once the server is able to identify you, it will generate a [Bookmarklet](https://en.wikipedia.org/wiki/Bookmarklet) that will allow you to actually capture pages in your browser and send them to RSSLater.

### Feed URL

Next to the bookmarklet section, there will also be a private RSS feed URL. This will be how the items actually get into your RSS reader.

## License

```
MIT License

Copyright (c) 2022 Nicholas Comer

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

