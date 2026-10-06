# wyrd-http

Shared HTTP transport for MCP servers. The Reader uses this package for bind parsing, token validation, TLS material validation, and its listener.

`readHttpArg(argv)` accepts `--http <port>` or `--http <host>:<port>`. A non-loopback numeric address also requires `--http-public`. It returns the validated bind or the same diagnostic used by the Reader.

Token helpers decode canonical 32-byte base64url values, read a bounded token file, and compare Bearer credentials. TLS helpers parse paired certificate and key flags and validate certificate material before binding.

Run `npm test` from the workspace root to build and verify the package with the other workspace suites.

startHttp(options, deps?) owns routing, exact Origin checks, the request body cap, Node/Fetch bridging, SDK dispatch, and ordered shutdown. Its readAuthInfo({ authorization, signal }) callback returns an authenticated, unauthenticated, or unavailable decision. The refusals map supplies text and optional headers for each refusal; the Reader adapter supplies its existing wire envelopes.

`options.onServerError(error, shutdown)` is called if the listening server emits `error` after startup. The transport starts the same ordered shutdown as `close()` before calling it. `shutdown` resolves after admitted HTTP work drains; an embedding write server must also wait for its own admitted writes. The caller owns diagnostics and exit status.

The request signal still aborts on socket close. It is a transport signal and must not be treated as write cancellation. Scribe owns its write completion tracker; this library does not provide one.
