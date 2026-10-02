#ifndef HEADER_CURL_FINGERPRINT_H
#define HEADER_CURL_FINGERPRINT_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
#include "curl_setup.h"

/*
 * Client fingerprint description, parsed from the JSON document given with
 * CURLOPT_FINGERPRINT. The JSON uses the format produced by fingerprinting
 * services (ja3_text, ja4_r/ja4_ro, akamai_text, user_agent), plus optional
 * explicit overrides (see docs/libcurl/opts/CURLOPT_FINGERPRINT.md).
 */

#define FP_MAX_LIST     64
#define FP_MAX_SHORT    16

struct Curl_fp_h2_setting {
  uint16_t id;
  uint32_t value;
};

struct Curl_fp {
  /* TLS ClientHello */
  uint16_t ciphers[FP_MAX_LIST];
  size_t nciphers;
  uint16_t exts[FP_MAX_LIST];       /* extension order */
  size_t nexts;
  uint16_t groups[FP_MAX_LIST];     /* supported_groups */
  size_t ngroups;
  uint16_t sigalgs[FP_MAX_LIST];    /* signature_algorithms */
  size_t nsigalgs;
  uint16_t key_shares[FP_MAX_SHORT];
  size_t nkey_shares;
  uint16_t cert_comp[FP_MAX_SHORT]; /* compress_certificate algorithms */
  size_t ncert_comp;
  uint16_t dc_sigalgs[FP_MAX_SHORT]; /* delegated_credentials sigalgs */
  size_t ndc_sigalgs;
  uint8_t ec_point_formats[FP_MAX_SHORT];
  size_t nec_point_formats;
  uint16_t record_size_limit;
  uint16_t tls_max;                 /* e.g. 0x0304, 0 if unknown */

  /* HTTP/2 */
  struct Curl_fp_h2_setting h2_settings[FP_MAX_SHORT];
  size_t nh2_settings;
  uint32_t h2_window_update;        /* connection WINDOW_UPDATE increment */
  char h2_pseudo[5];                /* e.g. "mpas", zero terminated */
  BIT(has_tls);
  BIT(has_h2);
};

/* Parse the JSON fingerprint. Returns CURLE_BAD_FUNCTION_ARGUMENT
   when the document is not usable. */
CURLcode Curl_fp_parse(const char *json, struct Curl_fp *fp);

/* Return an allocated copy of the "user_agent" member or NULL. */
char *Curl_fp_user_agent(const char *json);

/* TRUE if the extension type is in the fingerprint's extension list */
bool Curl_fp_has_ext(const struct Curl_fp *fp, uint16_t type);

/* Return the initial stream window size from the fingerprint's
   SETTINGS_INITIAL_WINDOW_SIZE, or 0 when not given. */
uint32_t Curl_fp_h2_initial_window(const struct Curl_fp *fp);

#endif /* HEADER_CURL_FINGERPRINT_H */
