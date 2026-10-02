---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_FINGERPRINT
Section: 3
Source: libcurl
See-also:
  - CURLOPT_SSL_CIPHER_LIST (3)
  - CURLOPT_SSL_EC_CURVES (3)
  - CURLOPT_SSL_SIGNATURE_ALGORITHMS (3)
  - CURLOPT_USERAGENT (3)
Protocol:
  - TLS
  - HTTP
TLS-backend:
  - OpenSSL
Added-in: 8.23.0
---

# NAME

CURLOPT_FINGERPRINT - client TLS and HTTP/2 fingerprint to mimic

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_FINGERPRINT, char *json);
~~~

# DESCRIPTION

Pass a char pointer to a zero terminated JSON document describing the TLS
ClientHello and HTTP/2 connection preface of a client (for example a web
browser) that libcurl should reproduce. The format is the one reported by
common fingerprinting services:

## user_agent

Used as User-Agent unless CURLOPT_USERAGENT(3) is set before this option.

## ja3_text

`version,ciphers,extensions,groups,ec_point_formats` with decimal values.
Provides cipher order, extension order, supported groups and EC point
formats.

## ja4_r, ja4_ro

Raw JA4 strings. The signature algorithms (last part) are taken from these.
`ja4_ro` is used for ciphers and extension order when `ja3_text` is absent.

## akamai_text

`SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_HEADER_ORDER`, for example
`1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s`. Provides the HTTP/2
SETTINGS frame, the connection window increment and the order of the
request pseudo headers. PRIORITY frames are not sent.

## Optional overrides

`tls_ciphers`, `tls_extensions`, `tls_groups`, `tls_sigalgs`,
`tls_key_shares`, `tls_delegated_credentials` (arrays of numbers or `"0x..."`
strings), `tls_cert_compression` (array of `"zlib"`, `"brotli"`, `"zstd"`),
`tls_record_size_limit` (number), `h2_settings` (string), `h2_window_update`
(number) and `h2_pseudo_header_order` (string such as `"mpas"`).

Values a JA3/JA4 hash does not capture default to browser values: key shares
for the first group (plus the next one if the first is a post-quantum hybrid,
plus one more for Firefox), certificate compression zlib, brotli, zstd for
Firefox and brotli otherwise, delegated credentials for ECDSA P-256/384/521
and SHA-1, and a record size limit of 16385.

Extensions OpenSSL does not implement are added by libcurl: delegated
credentials, record size limit, ECH GREASE, ALPS (application settings, both
codepoints, advertising `h2`) and trust anchors (empty list). When a server
accepts ALPS, libcurl answers with the fingerprint's HTTP/2 SETTINGS in a
client EncryptedExtensions message, like Chrome.

Explicitly set CURLOPT_SSL_CIPHER_LIST(3), CURLOPT_TLS13_CIPHERS(3),
CURLOPT_SSL_EC_CURVES(3) and CURLOPT_SSL_SIGNATURE_ALGORITHMS(3) take
precedence over the fingerprint. GREASE values and extensions the TLS library
cannot produce are skipped.

The fingerprint is not applied to HTTPS proxy connections or QUIC.

This option needs OpenSSL with the client extension order patch (the
`OPENSSL_HAS_CLIENT_EXTENSION_ORDER` API).

The application does not have to keep the string around after setting this
option.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode result;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_FINGERPRINT,
                     "{\"ja3_text\":\"771,4865-4867-4866,0-23-65281-10-11,"
                     "29-23-24,0\"}");
    result = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.
CURLE_BAD_FUNCTION_ARGUMENT is returned when the JSON cannot be used and
CURLE_NOT_BUILT_IN when the TLS backend lacks support.
