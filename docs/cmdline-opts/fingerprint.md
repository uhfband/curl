---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: fingerprint
Arg: <file>
Help: Mimic a client TLS/HTTP2 fingerprint from JSON
Protocols: TLS HTTP
Added: 8.23.0
Category: tls http
Multi: single
See-also:
  - ciphers
  - curves
  - sigalgs
Example:
  - --fingerprint firefox.json $URL
---

# `--fingerprint`

Make the TLS ClientHello and the HTTP/2 connection setup look like the client
described in the JSON file `file` (use `-` for stdin, or pass the JSON
directly when it starts with `{`). The JSON uses the format of fingerprinting
services: `ja3_text`, `ja4_r`/`ja4_ro`, `akamai_text` and `user_agent`. The
libcurl documentation for the corresponding option describes the optional
override fields.

The `user_agent` is used unless --user-agent is given. Other request headers
a browser sends are not added; use --header for those.
