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

#include "fingerprint.h"

/*
 * Minimal JSON reader: only what is needed to pick members out of a flat
 * top-level object. Values are located as spans into the original text.
 */

#define FP_STRBUF 4096

static const char *json_ws(const char *p)
{
  while(*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
    p++;
  return p;
}

/* p points to the opening quote. Returns pointer after closing quote. */
static const char *json_skip_string(const char *p)
{
  if(*p != '\"')
    return NULL;
  p++;
  while(*p && *p != '\"') {
    if(*p == '\\') {
      p++;
      if(!*p)
        return NULL;
    }
    p++;
  }
  return (*p == '\"') ? p + 1 : NULL;
}

static const char *json_skip_value(const char *p, int depth)
{
  p = json_ws(p);
  if(depth > 16)
    return NULL;
  if(*p == '\"')
    return json_skip_string(p);
  if(*p == '{' || *p == '[') {
    char close = (*p == '{') ? '}' : ']';
    p = json_ws(p + 1);
    if(*p == close)
      return p + 1;
    for(;;) {
      if(close == '}') {
        p = json_skip_string(json_ws(p));
        if(!p)
          return NULL;
        p = json_ws(p);
        if(*p != ':')
          return NULL;
        p++;
      }
      p = json_skip_value(p, depth + 1);
      if(!p)
        return NULL;
      p = json_ws(p);
      if(*p == ',') {
        p++;
        continue;
      }
      if(*p == close)
        return p + 1;
      return NULL;
    }
  }
  /* number, true, false, null */
  if(!*p || *p == ',' || *p == '}' || *p == ']')
    return NULL;
  while(*p && *p != ',' && *p != '}' && *p != ']' &&
        *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n')
    p++;
  return p;
}

/* Find top-level member |key|. Sets |val| to the start of its value. */
static bool json_member(const char *json, const char *key, const char **val)
{
  const char *p = json_ws(json);
  size_t klen = strlen(key);

  if(*p != '{')
    return FALSE;
  p = json_ws(p + 1);
  if(*p == '}')
    return FALSE;
  for(;;) {
    const char *kstart = p + 1;
    const char *kend = json_skip_string(p);
    if(!kend)
      return FALSE;
    p = json_ws(kend);
    if(*p != ':')
      return FALSE;
    p = json_ws(p + 1);
    if(((size_t)(kend - 1 - kstart) == klen) && !memcmp(kstart, key, klen)) {
      *val = p;
      return TRUE;
    }
    p = json_skip_value(p, 0);
    if(!p)
      return FALSE;
    p = json_ws(p);
    if(*p != ',')
      return FALSE;
    p = json_ws(p + 1);
  }
}

static int hexval(char c)
{
  if(c >= '0' && c <= '9')
    return c - '0';
  if(c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if(c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

/* Decode the JSON string at |p| into |buf|. Returns the end of the string
   in the source, or NULL on error/truncation. */
static const char *json_decode_string(const char *p, char *buf, size_t size,
                                      size_t *plen)
{
  size_t n = 0;

  if(*p != '\"')
    return NULL;
  p++;
  while(*p && *p != '\"') {
    unsigned int c = (unsigned char)*p++;
    if(c == '\\') {
      c = (unsigned char)*p++;
      switch(c) {
      case 'n': c = '\n'; break;
      case 't': c = '\t'; break;
      case 'r': c = '\r'; break;
      case 'b': c = '\b'; break;
      case 'f': c = '\f'; break;
      case 'u': {
        int i;
        c = 0;
        for(i = 0; i < 4; i++) {
          int h = hexval(*p++);
          if(h < 0)
            return NULL;
          c = (c << 4) | (unsigned int)h;
        }
        if(c > 0x7f) {
          /* encode as UTF-8 (BMP only) */
          if(n + 3 >= size)
            return NULL;
          if(c < 0x800) {
            buf[n++] = (char)(0xc0 | (c >> 6));
          }
          else {
            buf[n++] = (char)(0xe0 | (c >> 12));
            buf[n++] = (char)(0x80 | ((c >> 6) & 0x3f));
          }
          c = 0x80 | (c & 0x3f);
        }
        break;
      }
      case 0:
        return NULL;
      default: /* '"', '\\', '/' */
        break;
      }
    }
    if(n + 1 >= size)
      return NULL;
    buf[n++] = (char)c;
  }
  if(*p != '\"')
    return NULL;
  buf[n] = 0;
  if(plen)
    *plen = n;
  return p + 1;
}

static bool json_get_str(const char *json, const char *key,
                         char *buf, size_t size)
{
  const char *v;
  if(!json_member(json, key, &v) || *v != '\"')
    return FALSE;
  return json_decode_string(v, buf, size, NULL) != NULL;
}

static bool json_get_uint(const char *json, const char *key, uint32_t *out)
{
  const char *v;
  char *end;
  unsigned long val;

  if(!json_member(json, key, &v))
    return FALSE;
  if(*v == '\"') {
    char buf[32];
    if(!json_decode_string(v, buf, sizeof(buf), NULL))
      return FALSE;
    val = strtoul(buf, &end, 0);
    if(end == buf || *end)
      return FALSE;
  }
  else {
    val = strtoul(v, &end, 10);
    if(end == v)
      return FALSE;
  }
  if(val > 0xffffffffUL)
    return FALSE;
  *out = (uint32_t)val;
  return TRUE;
}

typedef bool fp_name_cb(const char *name, uint16_t *out);

/* Read an array of 16-bit values. Items are numbers, numeric strings
   ("0x0403", "771") or names resolved via |namecb|.
   Returns -1 on error, 0 when absent, 1 when parsed. */
static int json_get_u16_array(const char *json, const char *key,
                              uint16_t *out, size_t max, size_t *pn,
                              fp_name_cb *namecb)
{
  const char *p;
  size_t n = 0;

  if(!json_member(json, key, &p))
    return 0;
  if(*p != '[')
    return -1;
  p = json_ws(p + 1);
  if(*p == ']') {
    *pn = 0;
    return 1;
  }
  for(;;) {
    unsigned long val;
    char *end;
    if(n >= max)
      return -1;
    if(*p == '\"') {
      char buf[64];
      uint16_t named;
      p = json_decode_string(p, buf, sizeof(buf), NULL);
      if(!p)
        return -1;
      val = strtoul(buf, &end, 0);
      if(end == buf || *end) {
        if(!namecb || !namecb(buf, &named))
          return -1;
        val = named;
      }
    }
    else {
      val = strtoul(p, &end, 10);
      if(end == p)
        return -1;
      p = end;
    }
    if(val > 0xffff)
      return -1;
    out[n++] = (uint16_t)val;
    p = json_ws(p);
    if(*p == ',') {
      p = json_ws(p + 1);
      continue;
    }
    if(*p == ']')
      break;
    return -1;
  }
  *pn = n;
  return 1;
}

static bool cert_comp_name(const char *name, uint16_t *out)
{
  if(!strcmp(name, "zlib"))
    *out = 1;
  else if(!strcmp(name, "brotli"))
    *out = 2;
  else if(!strcmp(name, "zstd"))
    *out = 3;
  else
    return FALSE;
  return TRUE;
}

static bool is_grease(uint16_t v)
{
  return ((v & 0x0f0f) == 0x0a0a) && ((v >> 8) == (v & 0xff));
}

/* Parse a |sep| separated list of numbers in |base| from s[0..len).
   GREASE values are skipped. */
static bool parse_num_list(const char *s, size_t len, char sep, int base,
                           uint16_t *out, size_t max, size_t *pn)
{
  const char *end = s + len;
  size_t n = 0;

  while(s < end) {
    char num[16];
    size_t i = 0;
    unsigned long val;
    char *e;
    while(s < end && *s != sep) {
      if(i + 1 >= sizeof(num))
        return FALSE;
      num[i++] = *s++;
    }
    num[i] = 0;
    if(s < end)
      s++; /* skip separator */
    if(!i)
      continue;
    val = strtoul(num, &e, base);
    if(*e || val > 0xffff)
      return FALSE;
    if(is_grease((uint16_t)val))
      continue;
    if(n >= max)
      return FALSE;
    out[n++] = (uint16_t)val;
  }
  *pn = n;
  return TRUE;
}

/* Return start and length of field |idx| in |s| split by |sep|. */
static bool get_field(const char *s, char sep, int idx,
                      const char **start, size_t *len)
{
  while(idx > 0) {
    s = strchr(s, sep);
    if(!s)
      return FALSE;
    s++;
    idx--;
  }
  *start = s;
  {
    const char *e = strchr(s, sep);
    *len = e ? (size_t)(e - s) : strlen(s);
  }
  return TRUE;
}

/* ja3_text: "771,ciphers,extensions,groups,ec_point_formats" */
static CURLcode parse_ja3(const char *ja3, struct Curl_fp *fp)
{
  const char *f;
  size_t len;
  size_t n;
  uint16_t tmp[FP_MAX_SHORT];
  size_t i;

  if(!get_field(ja3, ',', 1, &f, &len) ||
     !parse_num_list(f, len, '-', 10, fp->ciphers, FP_MAX_LIST,
                     &fp->nciphers))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  if(!get_field(ja3, ',', 2, &f, &len) ||
     !parse_num_list(f, len, '-', 10, fp->exts, FP_MAX_LIST, &fp->nexts))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  if(!get_field(ja3, ',', 3, &f, &len) ||
     !parse_num_list(f, len, '-', 10, fp->groups, FP_MAX_LIST, &fp->ngroups))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  if(!get_field(ja3, ',', 4, &f, &len) ||
     !parse_num_list(f, len, '-', 10, tmp, FP_MAX_SHORT, &n))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  for(i = 0; i < n; i++)
    fp->ec_point_formats[i] = (uint8_t)tmp[i];
  fp->nec_point_formats = n;
  fp->has_tls = TRUE;
  return CURLE_OK;
}

/* ja4 prefix: "t13d1717h2" */
static void parse_ja4_prefix(const char *ja4, struct Curl_fp *fp)
{
  if(strlen(ja4) >= 3 && (ja4[0] == 't' || ja4[0] == 'q')) {
    if(ja4[1] == '1' && ja4[2] == '3')
      fp->tls_max = 0x0304;
    else if(ja4[1] == '1' && ja4[2] == '2')
      fp->tls_max = 0x0303;
  }
}

/* ja4_r / ja4_ro: "t13d1717h2_ciphers_extensions_sigalgs" (hex lists) */
static CURLcode parse_ja4_raw(const char *ja4, struct Curl_fp *fp,
                              bool want_order)
{
  const char *f;
  size_t len;

  parse_ja4_prefix(ja4, fp);
  if(get_field(ja4, '_', 3, &f, &len) && !fp->nsigalgs) {
    if(!parse_num_list(f, len, ',', 16, fp->sigalgs, FP_MAX_LIST,
                       &fp->nsigalgs))
      return CURLE_BAD_FUNCTION_ARGUMENT;
  }
  if(want_order && !fp->has_tls) {
    /* only the "original order" variant may serve as cipher/ext source */
    if(!get_field(ja4, '_', 1, &f, &len) ||
       !parse_num_list(f, len, ',', 16, fp->ciphers, FP_MAX_LIST,
                       &fp->nciphers))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    if(!get_field(ja4, '_', 2, &f, &len) ||
       !parse_num_list(f, len, ',', 16, fp->exts, FP_MAX_LIST, &fp->nexts))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    fp->has_tls = TRUE;
  }
  return CURLE_OK;
}

static CURLcode parse_h2_settings(const char *s, struct Curl_fp *fp)
{
  size_t n = 0;

  while(*s) {
    unsigned long id, val;
    char *end;
    id = strtoul(s, &end, 10);
    if(end == s || *end != ':' || id > 0xffff)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    s = end + 1;
    val = strtoul(s, &end, 10);
    if(end == s || val > 0xffffffffUL)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    if(n >= FP_MAX_SHORT)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    fp->h2_settings[n].id = (uint16_t)id;
    fp->h2_settings[n].value = (uint32_t)val;
    n++;
    s = end;
    if(*s == ';' || *s == ',')
      s++;
    else if(*s)
      return CURLE_BAD_FUNCTION_ARGUMENT;
  }
  fp->nh2_settings = n;
  fp->has_h2 = TRUE;
  return CURLE_OK;
}

static CURLcode parse_h2_pseudo(const char *s, struct Curl_fp *fp)
{
  size_t n = 0;

  for(; *s; s++) {
    char c = *s;
    if(c == ',' || c == ' ')
      continue;
    if(c == ':') /* allow ":method,:path,..." style */
      continue;
    if(c != 'm' && c != 'p' && c != 'a' && c != 's')
      return CURLE_BAD_FUNCTION_ARGUMENT;
    if(n >= 4 || memchr(fp->h2_pseudo, c, n))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    fp->h2_pseudo[n++] = c;
    /* skip the rest of a long name like "method" */
    while(s[1] && s[1] != ',' && s[1] != ' ')
      s++;
  }
  if(n != 4)
    return CURLE_BAD_FUNCTION_ARGUMENT;
  fp->h2_pseudo[4] = 0;
  fp->has_h2 = TRUE;
  return CURLE_OK;
}

/* akamai_text: "SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_HEADER_ORDER" */
static CURLcode parse_akamai(const char *ak, struct Curl_fp *fp)
{
  char buf[256];
  const char *f;
  size_t len;
  CURLcode result;

  if(!get_field(ak, '|', 0, &f, &len) || len >= sizeof(buf))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  memcpy(buf, f, len);
  buf[len] = 0;
  result = parse_h2_settings(buf, fp);
  if(result)
    return result;
  if(get_field(ak, '|', 1, &f, &len)) {
    char *end;
    unsigned long v = strtoul(f, &end, 10);
    if(end != f + len || v > 0x7fffffffUL)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    fp->h2_window_update = (uint32_t)v;
  }
  /* field 2 is the list of PRIORITY frames; not reproduced */
  if(get_field(ak, '|', 3, &f, &len)) {
    if(len >= sizeof(buf))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    memcpy(buf, f, len);
    buf[len] = 0;
    return parse_h2_pseudo(buf, fp);
  }
  return CURLE_OK;
}

static bool is_pq_hybrid(uint16_t group)
{
  return group == 0x11ec || /* X25519MLKEM768 */
         group == 0x11eb || /* SecP256r1MLKEM768 */
         group == 0x11ed || /* SecP384r1MLKEM1024 */
         group == 0x6399;   /* X25519Kyber768Draft00 */
}

bool Curl_fp_has_ext(const struct Curl_fp *fp, uint16_t type)
{
  size_t i;
  for(i = 0; i < fp->nexts; i++)
    if(fp->exts[i] == type)
      return TRUE;
  return FALSE;
}

uint32_t Curl_fp_h2_initial_window(const struct Curl_fp *fp)
{
  size_t i;
  for(i = 0; i < fp->nh2_settings; i++)
    if(fp->h2_settings[i].id == 4) /* SETTINGS_INITIAL_WINDOW_SIZE */
      return fp->h2_settings[i].value;
  return 0;
}

CURLcode Curl_fp_parse(const char *json, struct Curl_fp *fp)
{
  char *buf;
  CURLcode result = CURLE_BAD_FUNCTION_ARGUMENT;
  bool firefox = FALSE;
  uint32_t num;
  int rc;

  memset(fp, 0, sizeof(*fp));
  if(!json)
    return CURLE_BAD_FUNCTION_ARGUMENT;
  if(!json_skip_value(json, 0) || *json_ws(json) != '{')
    return CURLE_BAD_FUNCTION_ARGUMENT;

  buf = curlx_malloc(FP_STRBUF);
  if(!buf)
    return CURLE_OUT_OF_MEMORY;

  if(json_get_str(json, "user_agent", buf, FP_STRBUF))
    firefox = strstr(buf, "Firefox/") != NULL;

  if(json_get_str(json, "ja3_text", buf, FP_STRBUF) ||
     json_get_str(json, "ja3", buf, FP_STRBUF)) {
    result = parse_ja3(buf, fp);
    if(result)
      goto out;
  }
  if(json_get_str(json, "ja4_ro", buf, FP_STRBUF)) {
    result = parse_ja4_raw(buf, fp, TRUE);
    if(result)
      goto out;
  }
  if(json_get_str(json, "ja4_r", buf, FP_STRBUF)) {
    result = parse_ja4_raw(buf, fp, FALSE);
    if(result)
      goto out;
  }
  if(json_get_str(json, "ja4", buf, FP_STRBUF))
    parse_ja4_prefix(buf, fp);

  if(json_get_str(json, "akamai_text", buf, FP_STRBUF) ||
     json_get_str(json, "akamai", buf, FP_STRBUF)) {
    result = parse_akamai(buf, fp);
    if(result)
      goto out;
  }

  /* explicit overrides */
  result = CURLE_BAD_FUNCTION_ARGUMENT;
#define FP_ARRAY(key, field, count, cb)                                     \
  rc = json_get_u16_array(json, key, fp->field, CURL_ARRAYSIZE(fp->field), \
                          &fp->count, cb);                                \
  if(rc < 0)                                                              \
    goto out;
  FP_ARRAY("tls_ciphers", ciphers, nciphers, NULL)
  if(rc > 0)
    fp->has_tls = TRUE;
  FP_ARRAY("tls_extensions", exts, nexts, NULL)
  if(rc > 0)
    fp->has_tls = TRUE;
  FP_ARRAY("tls_groups", groups, ngroups, NULL)
  FP_ARRAY("tls_sigalgs", sigalgs, nsigalgs, NULL)
  FP_ARRAY("tls_key_shares", key_shares, nkey_shares, NULL)
  FP_ARRAY("tls_cert_compression", cert_comp, ncert_comp, cert_comp_name)
  FP_ARRAY("tls_delegated_credentials", dc_sigalgs, ndc_sigalgs, NULL)
#undef FP_ARRAY
  if(json_get_uint(json, "tls_record_size_limit", &num)) {
    if(num < 64 || num > 0x4001)
      goto out;
    fp->record_size_limit = (uint16_t)num;
  }
  if(json_get_str(json, "h2_settings", buf, FP_STRBUF) &&
     parse_h2_settings(buf, fp))
    goto out;
  if(json_get_uint(json, "h2_window_update", &num)) {
    if(num > 0x7fffffffUL)
      goto out;
    fp->h2_window_update = num;
    fp->has_h2 = TRUE;
  }
  if(json_get_str(json, "h2_pseudo_header_order", buf, FP_STRBUF) &&
     parse_h2_pseudo(buf, fp))
    goto out;

  if(!fp->has_tls && !fp->has_h2)
    goto out;

  /* defaults for values a JA3/JA4 hash does not capture */
  if(!fp->nkey_shares && fp->ngroups) {
    size_t want = 1;
    if(is_pq_hybrid(fp->groups[0]))
      want++;
    if(firefox) /* Firefox sends one more classic share (P-256) */
      want++;
    if(want > fp->ngroups)
      want = fp->ngroups;
    memcpy(fp->key_shares, fp->groups, want * sizeof(uint16_t));
    fp->nkey_shares = want;
  }
  if(!fp->ncert_comp && Curl_fp_has_ext(fp, 27)) {
    if(firefox) {
      fp->cert_comp[0] = 1; /* zlib */
      fp->cert_comp[1] = 2; /* brotli */
      fp->cert_comp[2] = 3; /* zstd */
      fp->ncert_comp = 3;
    }
    else {
      fp->cert_comp[0] = 2; /* brotli */
      fp->ncert_comp = 1;
    }
  }
  if(!fp->ndc_sigalgs && Curl_fp_has_ext(fp, 34)) {
    fp->dc_sigalgs[0] = 0x0403;
    fp->dc_sigalgs[1] = 0x0503;
    fp->dc_sigalgs[2] = 0x0603;
    fp->dc_sigalgs[3] = 0x0203;
    fp->ndc_sigalgs = 4;
  }
  if(!fp->record_size_limit)
    fp->record_size_limit = 0x4001;
  result = CURLE_OK;

out:
  curlx_free(buf);
  if(result)
    memset(fp, 0, sizeof(*fp));
  return result;
}

char *Curl_fp_user_agent(const char *json)
{
  const char *v;
  char *buf;
  size_t len = 0;

  if(!json || !json_member(json, "user_agent", &v) || *v != '\"')
    return NULL;
  /* decoded length is never longer than the encoded one */
  {
    const char *end = json_skip_string(v);
    if(!end)
      return NULL;
    len = (size_t)(end - v);
  }
  buf = curlx_malloc(len + 4);
  if(!buf)
    return NULL;
  if(!json_decode_string(v, buf, len + 4, NULL) || !buf[0]) {
    curlx_free(buf);
    return NULL;
  }
  return buf;
}
