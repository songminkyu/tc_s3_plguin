/*
 * aws_s3.c  -  AWS S3 REST API via WinHTTP + AWS Signature Version 4
 *
 * Implements:
 * - HMAC-SHA256 (via Windows CNG / BCrypt)
 * - SHA256 hash  (via Windows CNG / BCrypt)
 * - AWS SigV4 canonical request & authorization header
 * - WinHTTP-based HTTP GET / PUT / DELETE
 * - Tiny XML parser (just enough for S3 XML responses)
 * - INI-style credentials file reader
 */
#define _CRT_SECURE_NO_WARNINGS
#include "aws_s3.h"

#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <stdint.h>
#include <shlobj.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

/* ════════════════════════════════════════════════
   1.  SHA-256 / HMAC-SHA256  (Windows BCrypt)
   ════════════════════════════════════════════════ */

#define SHA256_DIGEST_LEN 32

static int sha256_raw(const BYTE* data, DWORD datalen, BYTE out[SHA256_DIGEST_LEN]) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD cbHash = 0, cbData = 0;
    BYTE* hashObj = NULL;
    DWORD hashObjSize = 0;
    int ok = 0;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0)))
        goto done;
    if (!BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                                          (PBYTE)&hashObjSize, sizeof(DWORD), &cbData, 0)))
        goto done;
    hashObj = (BYTE*)malloc(hashObjSize);
    if (!hashObj) goto done;
    if (!BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH,
                                          (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0)))
        goto done;
    if (cbHash != SHA256_DIGEST_LEN) goto done;
    if (!BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, hashObj, hashObjSize, NULL, 0, 0)))
        goto done;
    if (!BCRYPT_SUCCESS(BCryptHashData(hHash, (PUCHAR)data, datalen, 0)))
        goto done;
    if (!BCRYPT_SUCCESS(BCryptFinishHash(hHash, out, SHA256_DIGEST_LEN, 0)))
        goto done;
    ok = 1;
done:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);
    if (hashObj) free(hashObj);
    return ok;
}

static int hmac_sha256(const BYTE* key, DWORD keylen,
                        const BYTE* data, DWORD datalen,
                        BYTE out[SHA256_DIGEST_LEN]) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD cbData = 0, objSize = 0;
    BYTE* hashObj = NULL;
    int ok = 0;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM,
                                                     NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG)))
        goto done;
    if (!BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                                          (PBYTE)&objSize, sizeof(DWORD), &cbData, 0)))
        goto done;
    hashObj = (BYTE*)malloc(objSize);
    if (!hashObj) goto done;
    if (!BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, hashObj, objSize,
                                          (PUCHAR)key, keylen, 0)))
        goto done;
    if (!BCRYPT_SUCCESS(BCryptHashData(hHash, (PUCHAR)data, datalen, 0)))
        goto done;
    if (!BCRYPT_SUCCESS(BCryptFinishHash(hHash, out, SHA256_DIGEST_LEN, 0)))
        goto done;
    ok = 1;
done:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);
    if (hashObj) free(hashObj);
    return ok;
}

static void bytes_to_hex(const BYTE* bytes, int len, char* hex) {
    static const char tbl[] = "0123456789abcdef";
    for (int i = 0; i < len; i++) {
        hex[i*2]   = tbl[(bytes[i] >> 4) & 0xF];
        hex[i*2+1] = tbl[bytes[i] & 0xF];
    }
    hex[len*2] = '\0';
}

/* ════════════════════════════════════════════════
   2.  URI-encode helpers
   ════════════════════════════════════════════════ */

static int is_unreserved(char c) {
    return isalnum((unsigned char)c) ||
           c == '-' || c == '_' || c == '.' || c == '~';
}

static void uri_encode(const char* in, char* out, size_t out_max, int encode_slash) {
    size_t j = 0;
    for (size_t i = 0; in[i] && j+4 < out_max; i++) {
        unsigned char c = (unsigned char)in[i];
        if (is_unreserved(c) || (!encode_slash && c == '/')) {
            out[j++] = (char)c;
        } else {
            j += (size_t)sprintf(out+j, "%%%02X", c);
        }
    }
    out[j] = '\0';
}

/* ════════════════════════════════════════════════
   3.  AWS SigV4  (HMAC-SHA256 based)
   ════════════════════════════════════════════════ */

typedef struct {
    char access_key[AWS_MAX_KEY_LEN];
    char secret_key[AWS_MAX_KEY_LEN];
    char region[AWS_MAX_REGION_LEN];
    char service[32];            /* "s3" */
} AwsCredentials;

static void get_aws_datetime(char amzdate[17], char datestamp[9]) {
    SYSTEMTIME st;
    GetSystemTime(&st);
    sprintf(amzdate, "%04d%02d%02dT%02d%02d%02dZ",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond);
    sprintf(datestamp, "%04d%02d%02d",
            st.wYear, st.wMonth, st.wDay);
}

static void sign_request(const AwsCredentials* cred,
                          const char* method,
                          const char* uri,         /* url-encoded */
                          const char* query,
                          const char* canonical_headers,
                          const char* signed_headers,
                          const char* payload_hash,
                          const char* amzdate,
                          const char* datestamp,
                          char* out_auth, size_t out_auth_max) {
    /* ── 1. Canonical Request ── */
    char canonical_request[8192];
    snprintf(canonical_request, sizeof(canonical_request),
             "%s\n%s\n%s\n%s\n%s\n%s",
             method, uri, query,
             canonical_headers, signed_headers, payload_hash);

    BYTE cr_hash[SHA256_DIGEST_LEN];
    sha256_raw((const BYTE*)canonical_request, (DWORD)strlen(canonical_request), cr_hash);
    char cr_hex[65];
    bytes_to_hex(cr_hash, SHA256_DIGEST_LEN, cr_hex);

    /* ── 2. String to Sign ── */
    char credential_scope[128];
    snprintf(credential_scope, sizeof(credential_scope),
             "%s/%s/%s/aws4_request", datestamp, cred->region, cred->service);

    char string_to_sign[1024];
    snprintf(string_to_sign, sizeof(string_to_sign),
             "AWS4-HMAC-SHA256\n%s\n%s\n%s",
             amzdate, credential_scope, cr_hex);

    /* ── 3. Signing Key ── */
    char k_secret_str[AWS_MAX_KEY_LEN + 5];
    snprintf(k_secret_str, sizeof(k_secret_str), "AWS4%s", cred->secret_key);

    BYTE k_date[SHA256_DIGEST_LEN];
    BYTE k_region[SHA256_DIGEST_LEN];
    BYTE k_service[SHA256_DIGEST_LEN];
    BYTE k_signing[SHA256_DIGEST_LEN];

    hmac_sha256((BYTE*)k_secret_str, (DWORD)strlen(k_secret_str),
                (BYTE*)datestamp, (DWORD)strlen(datestamp), k_date);
    hmac_sha256(k_date, SHA256_DIGEST_LEN,
                (BYTE*)cred->region, (DWORD)strlen(cred->region), k_region);
    hmac_sha256(k_region, SHA256_DIGEST_LEN,
                (BYTE*)cred->service, (DWORD)strlen(cred->service), k_service);
    BYTE aws4_request[] = "aws4_request";
    hmac_sha256(k_service, SHA256_DIGEST_LEN,
                aws4_request, sizeof(aws4_request)-1, k_signing);

    /* ── 4. Signature ── */
    BYTE sig_bytes[SHA256_DIGEST_LEN];
    hmac_sha256(k_signing, SHA256_DIGEST_LEN,
                (BYTE*)string_to_sign, (DWORD)strlen(string_to_sign), sig_bytes);
    char sig_hex[65];
    bytes_to_hex(sig_bytes, SHA256_DIGEST_LEN, sig_hex);

    /* ── 5. Authorization header ── */
    snprintf(out_auth, out_auth_max,
             "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
             cred->access_key, credential_scope, signed_headers, sig_hex);
}

/* ════════════════════════════════════════════════
   4.  WinHTTP helpers
   ════════════════════════════════════════════════ */

struct S3Context {
    AwsCredentials cred;
    HINTERNET      hSession;
};

static wchar_t* a2w(const char* s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    wchar_t* w = (wchar_t*)malloc(n * sizeof(wchar_t));
    if (w) MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    return w;
}

static char* w2a(const wchar_t* w) {
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    char* a = (char*)malloc(n);
    if (a) WideCharToMultiByte(CP_UTF8, 0, w, -1, a, n, NULL, NULL);
    return a;
}

static const char* EMPTY_BODY_HASH =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

typedef struct { char* data; size_t len; size_t cap; } GrowBuf;

static void gbuf_append(GrowBuf* g, const char* s, size_t n) {
    if (g->len + n + 1 > g->cap) {
        g->cap = (g->len + n + 1) * 2 + 4096;
        g->data = (char*)realloc(g->data, g->cap);
    }
    if (g->data) {
        memcpy(g->data + g->len, s, n);
        g->len += n;
        g->data[g->len] = '\0';
    }
}

static int s3_http_request(S3Context* ctx,
                            const char* bucket,
                            const char* key,
                            const char* query,
                            const char* method,
                            const BYTE* body, DWORD body_len,
                            char** out_body,
                            DWORD* out_status) {
    char host[256], path[AWS_MAX_PATH_LEN+2];
    char uri_encoded[AWS_MAX_PATH_LEN*3+2];

    if (bucket && *bucket) {
        snprintf(host, sizeof(host), "%s.s3.%s.amazonaws.com", bucket, ctx->cred.region);
        if (key && *key) {
            char raw_path[AWS_MAX_PATH_LEN+2];
            snprintf(raw_path, sizeof(raw_path), "/%s", key);
            strcpy(path, "/");
            char seg[AWS_MAX_PATH_LEN];
            const char* p = key;
            const char* slash;
            uri_encoded[0] = '/'; uri_encoded[1] = '\0';
            while ((slash = strchr(p, '/')) != NULL) {
                size_t seglen = (size_t)(slash - p);
                strncpy(seg, p, seglen); seg[seglen] = '\0';
                char enc[AWS_MAX_PATH_LEN*3];
                uri_encode(seg, enc, sizeof(enc), 1);
                strncat(uri_encoded, enc, sizeof(uri_encoded)-strlen(uri_encoded)-1);
                strncat(uri_encoded, "/", sizeof(uri_encoded)-strlen(uri_encoded)-1);
                p = slash+1;
            }
            char enc[AWS_MAX_PATH_LEN*3];
            uri_encode(p, enc, sizeof(enc), 1);
            strncat(uri_encoded, enc, sizeof(uri_encoded)-strlen(uri_encoded)-1);
            strcpy(path, uri_encoded);
        } else {
            strcpy(path, "/");
            strcpy(uri_encoded, "/");
        }
    } else {
        if (ctx->cred.region && *(ctx->cred.region) && strcmp(ctx->cred.region, "us-east-1") != 0) {
            snprintf(host, sizeof(host), "s3.%s.amazonaws.com", ctx->cred.region);
        } else {
            snprintf(host, sizeof(host), "s3.amazonaws.com");
        }
        strcpy(path, "/");
        strcpy(uri_encoded, "/");
    }

    char payload_hash[65];
    if (body && body_len > 0) {
        BYTE h[SHA256_DIGEST_LEN];
        sha256_raw(body, body_len, h);
        bytes_to_hex(h, SHA256_DIGEST_LEN, payload_hash);
    } else {
        strcpy(payload_hash, EMPTY_BODY_HASH);
    }

    char amzdate[17], datestamp[9];
    get_aws_datetime(amzdate, datestamp);

    char canonical_headers[1024];
    snprintf(canonical_headers, sizeof(canonical_headers),
             "host:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n",
             host, payload_hash, amzdate);
    const char* signed_headers = "host;x-amz-content-sha256;x-amz-date";

    char auth[1024];
    sign_request(&ctx->cred, method,
                 uri_encoded,
                 query ? query : "",
                 canonical_headers,
                 signed_headers,
                 payload_hash,
                 amzdate, datestamp,
                 auth, sizeof(auth));

    char path_and_query[AWS_MAX_PATH_LEN + 1024];
    if (query && *query)
        snprintf(path_and_query, sizeof(path_and_query), "%s?%s", path, query);
    else
        snprintf(path_and_query, sizeof(path_and_query), "%s", path);

    wchar_t* whost   = a2w(host);
    wchar_t* wpathq  = a2w(path_and_query);
    wchar_t* wmethod = a2w(method);

    if (!whost || !wpathq || !wmethod) {
        free(whost); free(wpathq); free(wmethod);
        if (out_status) *out_status = 0;
        return 0;
    }

    if (!ctx->hSession) {
        free(whost); free(wpathq); free(wmethod);
        if (out_status) *out_status = 0;
        SetLastError(ERROR_INVALID_HANDLE);
        return 0;
    }

    HINTERNET hConn = WinHttpConnect(ctx->hSession, whost, INTERNET_DEFAULT_HTTPS_PORT, 0);
    free(whost);
    if (!hConn) {
        DWORD err = GetLastError();
        free(wpathq); free(wmethod);
        if (out_status) *out_status = 0;
        SetLastError(err);
        return 0;
    }

    HINTERNET hReq = WinHttpOpenRequest(hConn, wmethod, wpathq, NULL,
                                         WINHTTP_NO_REFERER,
                                         WINHTTP_DEFAULT_ACCEPT_TYPES,
                                         WINHTTP_FLAG_SECURE);
    free(wpathq);
    free(wmethod);
    if (!hReq) {
        DWORD err = GetLastError();
        WinHttpCloseHandle(hConn);
        if (out_status) *out_status = 0;
        SetLastError(err);
        return 0;
    }

    DWORD dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));

    DWORD dwRedirect = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    WinHttpSetOption(hReq, WINHTTP_OPTION_REDIRECT_POLICY, &dwRedirect, sizeof(DWORD));

    DWORD dwAutoLogon = WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH;
    WinHttpSetOption(hReq, WINHTTP_OPTION_AUTOLOGON_POLICY, &dwAutoLogon, sizeof(DWORD));

    DWORD timeout_ms = 30000;
    WinHttpSetOption(hReq, WINHTTP_OPTION_CONNECT_TIMEOUT,    &timeout_ms, sizeof(DWORD));
    WinHttpSetOption(hReq, WINHTTP_OPTION_SEND_TIMEOUT,       &timeout_ms, sizeof(DWORD));
    WinHttpSetOption(hReq, WINHTTP_OPTION_RECEIVE_TIMEOUT,    &timeout_ms, sizeof(DWORD));

    char hdr[2048];
    wchar_t* wh;

    snprintf(hdr, sizeof(hdr), "x-amz-date: %s", amzdate);
    wh = a2w(hdr); WinHttpAddRequestHeaders(hReq, wh, -1L, WINHTTP_ADDREQ_FLAG_ADD); free(wh);

    snprintf(hdr, sizeof(hdr), "x-amz-content-sha256: %s", payload_hash);
    wh = a2w(hdr); WinHttpAddRequestHeaders(hReq, wh, -1L, WINHTTP_ADDREQ_FLAG_ADD); free(wh);

    snprintf(hdr, sizeof(hdr), "Authorization: %s", auth);
    wh = a2w(hdr); WinHttpAddRequestHeaders(hReq, wh, -1L, WINHTTP_ADDREQ_FLAG_ADD); free(wh);

    if (!body || body_len == 0) {
        wh = a2w("Content-Length: 0");
        WinHttpAddRequestHeaders(hReq, wh, -1L, WINHTTP_ADDREQ_FLAG_ADD);
        free(wh);
    }

    DWORD err = 0;
    BOOL ok = WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                  (LPVOID)body, body_len, body_len, 0);
    if (!ok) err = GetLastError();
    if (ok) {
        ok = WinHttpReceiveResponse(hReq, NULL);
        if (!ok) err = GetLastError();
    }

    DWORD status = 0, sz = sizeof(DWORD);
    if (ok) WinHttpQueryHeaders(hReq,
                                 WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                 WINHTTP_HEADER_NAME_BY_INDEX,
                                 &status, &sz, WINHTTP_NO_HEADER_INDEX);
    if (out_status) *out_status = status;

    if (ok && out_body) {
        GrowBuf gb = {0};
        DWORD avail = 0;
        while (WinHttpQueryDataAvailable(hReq, &avail) && avail > 0) {
            char* chunk = (char*)malloc(avail + 1);
            if (chunk) {
                DWORD nread = 0;
                WinHttpReadData(hReq, chunk, avail, &nread);
                gbuf_append(&gb, chunk, nread);
                free(chunk);
            }
        }
        if (gb.data) {
            gb.data[gb.len] = '\0'; /* 안정적인 종료 문자 보장 */
        }
        *out_body = gb.data;
    }

    if (status != 0 && (status < 200 || status >= 300)) {
        char err_log_path[MAX_PATH];
        GetTempPathA(MAX_PATH, err_log_path);
        strncat(err_log_path, "tc_s3_http_error.txt", MAX_PATH - strlen(err_log_path) - 1);
        FILE* ef = fopen(err_log_path, "w");
        if (ef) {
            fprintf(ef, "Method: %s\nHost: %s\nPath: %s\nHTTP Status: %lu\nResponse Body:\n%s\n",
                    method, host, path_and_query, status, (out_body && *out_body) ? *out_body : "(none)");
            fclose(ef);
        }
    }

    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConn);

    if (!ok && err) SetLastError(err);
    return (status >= 200 && status < 300) ? 1 : 0;
}

/* ════════════════════════════════════════════════
   5.  Tiny XML text-extractor (no external parser)
   ════════════════════════════════════════════════ */

static const char* xml_first(const char* xml, const char* tag,
                               char* buf, size_t out_max) {
    char open[64], close[64];
    snprintf(open,  sizeof(open),  "<%s>",  tag);
    snprintf(close, sizeof(close), "</%s>", tag);
    const char* s = strstr(xml, open);
    if (!s) return NULL;
    s += strlen(open);
    const char* e = strstr(s, close);
    if (!e) return NULL;
    size_t n = (size_t)(e - s);
    if (n >= out_max) n = out_max - 1;
    memcpy(buf, s, n);
    buf[n] = '\0';
    return e + strlen(close);
}

typedef void (*xml_iter_cb)(const char* inner, void* user);

/* [CRITICAL FIX] 복잡한 내부 Depth 태그 구조에서 포인터 유실을 방지하는 안전망 설계 */
static void xml_iter(const char* xml, const char* tag, xml_iter_cb cb, void* user) {
    char open[64], close[64];
    snprintf(open,  sizeof(open),  "<%s>",  tag);
    snprintf(close, sizeof(close), "</%s>", tag);
    const char* p = xml;
    while (p) {
        const char* s = strstr(p, open);
        if (!s) break;
        const char* next_search_start = s + strlen(open);
        const char* e = strstr(next_search_start, close);
        if (!e) break;
        
        size_t n = (size_t)(e - next_search_start);
        char* inner = (char*)malloc(n + 1);
        if (inner) {
            memcpy(inner, next_search_start, n);
            inner[n] = '\0';
            cb(inner, user);
            free(inner);
        }
        p = e + strlen(close);
    }
}

/* ════════════════════════════════════════════════
   6.  S3Context lifecycle
   ════════════════════════════════════════════════ */

S3Context* s3_create(const char* access_key_id,
                     const char* secret_access_key,
                     const char* region) {
    S3Context* ctx = (S3Context*)calloc(1, sizeof(S3Context));
    if (!ctx) return NULL;
    strncpy(ctx->cred.access_key, access_key_id, AWS_MAX_KEY_LEN-1);
    strncpy(ctx->cred.secret_key, secret_access_key, AWS_MAX_KEY_LEN-1);
    strncpy(ctx->cred.region,     region,            AWS_MAX_REGION_LEN-1);
    strcpy(ctx->cred.service, "s3");
    ctx->hSession = WinHttpOpen(L"TC-S3-Plugin/1.0",
                                 WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                 WINHTTP_NO_PROXY_NAME,
                                 WINHTTP_NO_PROXY_BYPASS, 0);
    return ctx;
}

void s3_destroy(S3Context* ctx) {
    if (!ctx) return;
    if (ctx->hSession) WinHttpCloseHandle(ctx->hSession);
    free(ctx);
}

/* ════════════════════════════════════════════════
   7.  Profile loading (~/.aws/credentials INI)
   ════════════════════════════════════════════════ */

S3Profile** s3_load_profiles(int* out_count) {
    *out_count = 0;
    char home[MAX_PATH] = {0};
    if (SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, home) != S_OK) {
        GetEnvironmentVariableA("USERPROFILE", home, MAX_PATH);
    }
    char cred_path[MAX_PATH];
    snprintf(cred_path, sizeof(cred_path), "%s\\.aws\\credentials", home);

    FILE* f = fopen(cred_path, "r");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long fsz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char* content = (char*)malloc(fsz+1);
    if (!content) { fclose(f); return NULL; }
    size_t read_bytes = fread(content, 1, fsz, f);
    content[read_bytes] = '\0';
    fclose(f);

    S3Profile** profiles = NULL;
    int count = 0;

    char* line = strtok(content, "\n");
    S3Profile* cur = NULL;
    while (line) {
        char* cr = strchr(line, '\r');
        if (cr) *cr = '\0';
        
        while (*line == ' ' || *line == '\t') line++;

        if (line[0] == '[') {
            cur = (S3Profile*)calloc(1, sizeof(S3Profile));
            char* end = strchr(line+1, ']');
            if (end) {
                *end = '\0';
                char* sec_name = line + 1;
                char* d_p = strstr(sec_name, "default");
                if (d_p) {
                    strcpy(cur->name, "default");
                } else {
                    while (*sec_name == ' ' || *sec_name == '\t') sec_name++;
                    char* se = sec_name + strlen(sec_name) - 1;
                    while (se > sec_name && (*se == ' ' || *se == '\t')) *se-- = '\0';
                    strncpy(cur->name, sec_name, AWS_MAX_PROFILE_LEN-1);
                }
            }
            strcpy(cur->region, "us-east-1");
            profiles = (S3Profile**)realloc(profiles, (count+1)*sizeof(S3Profile*));
            profiles[count++] = cur;
        } else if (cur && *line) {
            char* eq = strchr(line, '=');
            if (eq) {
                *eq = '\0';
                char* key = line;
                char* val = eq+1;
                
                while (*key == ' ' || *key == '\t' || *key == '\r' || *key == '\n') key++;
                while (*val == ' ' || *val == '\t' || *val == '\r' || *val == '\n') val++;
                
                char* ke = key + strlen(key) - 1;
                while (ke > key && (*ke == ' ' || *ke == '\t' || *ke == '\r' || *ke == '\n')) *ke-- = '\0';
                char* ve = val + strlen(val) - 1;
                while (ve > val && (*ve == ' ' || *ve == '\t' || *ve == '\r' || *ve == '\n')) *ve-- = '\0';

                if (strcmp(key, "aws_access_key_id") == 0)
                    strncpy(cur->access_key_id, val, AWS_MAX_KEY_LEN-1);
                else if (strcmp(key, "aws_secret_access_key") == 0)
                    strncpy(cur->secret_access_key, val, AWS_MAX_KEY_LEN-1);
                else if (strcmp(key, "region") == 0)
                    strncpy(cur->region, val, AWS_MAX_REGION_LEN-1);
            }
        }
        line = strtok(NULL, "\n");
    }
    free(content);
    *out_count = count;
    return profiles;
}

void s3_free_profiles(S3Profile** profiles, int count) {
    if (!profiles) return;
    for (int i = 0; i < count; i++) free(profiles[i]);
    free(profiles);
}

/* ════════════════════════════════════════════════
   8.  Bucket operations
   ════════════════════════════════════════════════ */

static void parse_bucket_cb(const char* inner, void* user) {
    S3BucketEntry** head = (S3BucketEntry**)user;
    S3BucketEntry* e = (S3BucketEntry*)calloc(1, sizeof(S3BucketEntry));
    if (e) {
        xml_first(inner, "Name", e->name, sizeof(e->name));
        xml_first(inner, "CreationDate", e->creation_date, sizeof(e->creation_date));
        e->next = *head;
        *head = e;
    }
}

S3BucketEntry* s3_list_buckets(S3Context* ctx) {
    char* body = NULL;
    DWORD status = 0;
    int ok = s3_http_request(ctx, NULL, NULL, NULL, "GET", NULL, 0, &body, &status);
    if (!ok || !body) { free(body); return NULL; }

    S3BucketEntry* head = NULL;
    xml_iter(body, "Bucket", parse_bucket_cb, &head);
    free(body);

    S3BucketEntry* prev = NULL, *cur = head, *next;
    while (cur) { next = cur->next; cur->next = prev; prev = cur; cur = next; }
    return prev;
}

void s3_free_buckets(S3BucketEntry* list) {
    while (list) { S3BucketEntry* n = list->next; free(list); list = n; }
}

int s3_create_bucket(S3Context* ctx, const char* bucket_name) {
    char body_str[512] = "";
    DWORD body_len = 0;
    const BYTE* body = NULL;
    if (strcmp(ctx->cred.region, "us-east-1") != 0) {
        snprintf(body_str, sizeof(body_str),
                 "<CreateBucketConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
                 "<LocationConstraint>%s</LocationConstraint>"
                 "</CreateBucketConfiguration>",
                 ctx->cred.region);
        body_len = (DWORD)strlen(body_str);
        body = (const BYTE*)body_str;
    }
    DWORD status = 0;
    return s3_http_request(ctx, bucket_name, NULL, NULL, "PUT", body, body_len, NULL, &status);
}

int s3_delete_bucket(S3Context* ctx, const char* bucket_name) {
    DWORD status = 0;
    return s3_http_request(ctx, bucket_name, NULL, NULL, "DELETE", NULL, 0, NULL, &status);
}

/* ════════════════════════════════════════════════
   9.  Object listing
   ════════════════════════════════════════════════ */

typedef struct { S3Object* head; const char* prefix; } ObjCtx;

/* [CRITICAL FIX] S3 Contents 바디 매칭 안전성 보강 */
static void parse_content_cb(const char* inner, void* user) {
    ObjCtx* oc = (ObjCtx*)user;
    S3Object* e = (S3Object*)calloc(1, sizeof(S3Object));
    if (e) {
        xml_first(inner, "Key",          e->key,           sizeof(e->key));
        xml_first(inner, "LastModified", e->last_modified, sizeof(e->last_modified));
        char sz[32] = "0";
        xml_first(inner, "Size",         sz,               sizeof(sz));
        e->size = _atoi64(sz);
        e->is_prefix = 0;
        
        /* 만약 추출한 Key가 빈 값이거나 Prefix와 100% 일치하는 가상 디렉토리 오브젝트라면 리스트 바인딩 제외 */
        if (strlen(e->key) == 0 || (oc->prefix && strcmp(e->key, oc->prefix) == 0)) {
            free(e);
            return;
        }
        
        e->next = oc->head;
        oc->head = e;
    }
}

static void parse_prefix_cb(const char* inner, void* user) {
    ObjCtx* oc = (ObjCtx*)user;
    S3Object* e = (S3Object*)calloc(1, sizeof(S3Object));
    if (e) {
        char pfx[AWS_MAX_PATH_LEN] = {0};
        xml_first(inner, "Prefix", pfx, sizeof(pfx));
        if (strlen(pfx) == 0) {
            free(e);
            return;
        }
        strncpy(e->key, pfx, sizeof(e->key)-1);
        e->is_prefix = 1;
        e->next = oc->head;
        oc->head = e;
    }
}

/* ⭐️ [핵심 수정] AWS SigV4 규격을 완벽하게 따르도록 보정된 함수 */
S3Object* s3_list_objects(S3Context* ctx, const char* bucket,
                           const char* prefix, char delimiter) {
    char query[1024] = { 0 };
    
    /* * [AWS SigV4 규격] Query 파라미터는 알파벳 순서(ASCII 바이트 순)로 정렬해야 합니다.
     * 순서: delimiter -> list-type -> max-keys -> prefix
     */
    if (prefix && *prefix) {
        char enc_prefix[AWS_MAX_PATH_LEN * 3] = { 0 };
        // prefix 경로의 '/' 문자가 %2F로 안전하게 인코딩되도록 규칙 지정
        uri_encode(prefix, enc_prefix, sizeof(enc_prefix), 1);
        
        snprintf(query, sizeof(query), 
                 "delimiter=%%2F&list-type=2&max-keys=1000&prefix=%s", 
                 enc_prefix);
    } else {
        snprintf(query, sizeof(query), "delimiter=%%2F&list-type=2&max-keys=1000");
    }

    char* body = NULL;
    DWORD status = 0;
    SetLastError(0);
    int ok = s3_http_request(ctx, bucket, NULL, query, "GET", NULL, 0, &body, &status);
    DWORD win32_err = GetLastError();

    if (!ok) {
        char log_path[MAX_PATH];
        GetTempPathA(MAX_PATH, log_path);
        strncat(log_path, "tc_s3_error.txt", MAX_PATH - strlen(log_path) - 1);

        FILE* f = fopen(log_path, "w");
        if (f) {
            fprintf(f,
                "=== TC S3 Plugin: List Objects Error ===\n"
                "Bucket    : %s\n"
                "Prefix    : %s\n"
                "Query     : %s\n"
                "HTTP Status: %lu\n"
                "Win32 Error: %lu (0x%08lX)\n"
                "Response  :\n%s\n",
                bucket,
                prefix ? prefix : "(root)",
                query,
                status,
                win32_err, win32_err,
                body ? body : "(none - WinHTTP level failure)");
            fclose(f);
        }
        free(body);
        return NULL;
    }

    ObjCtx oc = { NULL, prefix };
    xml_iter(body, "Contents",     parse_content_cb, &oc);
    xml_iter(body, "CommonPrefixes", parse_prefix_cb, &oc);
    free(body);

    S3Object* prev = NULL, *cur = oc.head, *next;
    while (cur) { next = cur->next; cur->next = prev; prev = cur; cur = next; }
    return prev;
}

void s3_free_objects(S3Object* list) {
    while (list) { S3Object* n = list->next; free(list); list = n; }
}

/* ════════════════════════════════════════════════
   10.  Object get / put / delete / copy
   ════════════════════════════════════════════════ */

int s3_get_object(S3Context* ctx, const char* bucket, const char* key,
                  const char* local_path) {
    char* body = NULL;
    DWORD status = 0;
    int ok = s3_http_request(ctx, bucket, key, NULL, "GET", NULL, 0, &body, &status);
    if (!ok || !body) { free(body); return 0; }

    FILE* f = fopen(local_path, "wb");
    if (!f) { free(body); return 0; }
    fclose(f);
    free(body);

    char host[256];
    snprintf(host, sizeof(host), "%s.s3.%s.amazonaws.com", bucket, ctx->cred.region);

    char amzdate[17], datestamp[9];
    get_aws_datetime(amzdate, datestamp);

    char canonical_headers[512];
    snprintf(canonical_headers, sizeof(canonical_headers),
             "host:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n",
             host, EMPTY_BODY_HASH, amzdate);

    char uri_enc[AWS_MAX_PATH_LEN*3+2];
    uri_enc[0] = '/'; uri_enc[1] = '\0';
    char seg[AWS_MAX_PATH_LEN], enc[AWS_MAX_PATH_LEN*3];
    const char* p = key;
    const char* slash;
    while ((slash = strchr(p, '/')) != NULL) {
        size_t n = (size_t)(slash - p);
        strncpy(seg, p, n); seg[n] = '\0';
        uri_encode(seg, enc, sizeof(enc), 1);
        strncat(uri_enc, enc, sizeof(uri_enc)-strlen(uri_enc)-1);
        strncat(uri_enc, "/", sizeof(uri_enc)-strlen(uri_enc)-1);
        p = slash+1;
    }
    uri_encode(p, enc, sizeof(enc), 1);
    strncat(uri_enc, enc, sizeof(uri_enc)-strlen(uri_enc)-1);

    char auth[1024];
    sign_request(&ctx->cred, "GET", uri_enc, "",
                 canonical_headers, "host;x-amz-content-sha256;x-amz-date",
                 EMPTY_BODY_HASH, amzdate, datestamp, auth, sizeof(auth));

    wchar_t* whost2 = a2w(host);
    wchar_t* wpath2 = a2w(uri_enc);

    HINTERNET hConn = WinHttpConnect(ctx->hSession, whost2, INTERNET_DEFAULT_HTTPS_PORT, 0);
    free(whost2);
    if (!hConn) { free(wpath2); return 0; }

    HINTERNET hReq = WinHttpOpenRequest(hConn, L"GET", wpath2, NULL,
                                         WINHTTP_NO_REFERER,
                                         WINHTTP_DEFAULT_ACCEPT_TYPES,
                                         WINHTTP_FLAG_SECURE);
    free(wpath2);
    if (!hReq) { WinHttpCloseHandle(hConn); return 0; }

    DWORD dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));

    DWORD timeout_ms = 30000;
    WinHttpSetOption(hReq, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout_ms, sizeof(DWORD));

    char hdr[2048];
    wchar_t* wh;
    snprintf(hdr, sizeof(hdr), "x-amz-date: %s", amzdate);
    wh = a2w(hdr); WinHttpAddRequestHeaders(hReq, wh, -1L, WINHTTP_ADDREQ_FLAG_ADD); free(wh);
    snprintf(hdr, sizeof(hdr), "x-amz-content-sha256: %s", EMPTY_BODY_HASH);
    wh = a2w(hdr); WinHttpAddRequestHeaders(hReq, wh, -1L, WINHTTP_ADDREQ_FLAG_ADD); free(wh);
    snprintf(hdr, sizeof(hdr), "Authorization: %s", auth);
    wh = a2w(hdr); WinHttpAddRequestHeaders(hReq, wh, -1L, WINHTTP_ADDREQ_FLAG_ADD); free(wh);

    BOOL bok = WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0);
    if (bok) bok = WinHttpReceiveResponse(hReq, NULL);
    DWORD st = 0, sz2 = sizeof(DWORD);
    if (bok) WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                  WINHTTP_HEADER_NAME_BY_INDEX, &st, &sz2, WINHTTP_NO_HEADER_INDEX);

    int ret = 0;
    if (bok && st >= 200 && st < 300) {
        f = fopen(local_path, "wb");
        if (f) {
            DWORD avail = 0;
            while (WinHttpQueryDataAvailable(hReq, &avail) && avail > 0) {
                BYTE* chunk = (BYTE*)malloc(avail);
                if (chunk) {
                    DWORD rd = 0;
                    WinHttpReadData(hReq, chunk, avail, &rd);
                    fwrite(chunk, 1, rd, f);
                    free(chunk);
                }
            }
            fclose(f);
            ret = 1;
        }
    }
    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConn);
    return ret;
}

int s3_put_object(S3Context* ctx, const char* bucket, const char* key,
                  const char* local_path) {
    FILE* f = fopen(local_path, "rb");
    if (!f) return 0;
    fseek(f, 0, SEEK_END);
    long fsz = ftell(f);
    fseek(f, 0, SEEK_SET);
    BYTE* data = (BYTE*)malloc(fsz);
    if (!data) { fclose(f); return 0; }
    size_t rb = fread(data, 1, fsz, f);
    fclose(f);

    DWORD status = 0;
    int ok = s3_http_request(ctx, bucket, key, NULL, "PUT",
                              data, (DWORD)rb, NULL, &status);
    free(data);
    return ok;
}

int s3_put_folder(S3Context* ctx, const char* bucket, const char* key) {
    DWORD status = 0;
    return s3_http_request(ctx, bucket, key, NULL, "PUT", NULL, 0, NULL, &status);
}

int s3_delete_object(S3Context* ctx, const char* bucket, const char* key) {
    DWORD status = 0;
    return s3_http_request(ctx, bucket, key, NULL, "DELETE", NULL, 0, NULL, &status);
}

int s3_copy_object(S3Context* ctx,
                   const char* src_bucket, const char* src_key,
                   const char* dst_bucket, const char* dst_key) {
    char host[256];
    snprintf(host, sizeof(host), "%s.s3.%s.amazonaws.com", dst_bucket, ctx->cred.region);

    char copy_source[512];
    snprintf(copy_source, sizeof(copy_source), "/%s/%s", src_bucket, src_key);

    char amzdate[17], datestamp[9];
    get_aws_datetime(amzdate, datestamp);

    char uri_enc[AWS_MAX_PATH_LEN*3+2];
    uri_enc[0]='/'; uri_enc[1]='\0';
    const char* p=dst_key; const char* slash; char seg[AWS_MAX_PATH_LEN],enc[AWS_MAX_PATH_LEN*3];
    while((slash=strchr(p,'/'))) {
        size_t n=(size_t)(slash-p); strncpy(seg,p,n); seg[n]='\0';
        uri_encode(seg,enc,sizeof(enc),1);
        strncat(uri_enc,enc,sizeof(uri_enc)-strlen(uri_enc)-1);
        strncat(uri_enc,"/",sizeof(uri_enc)-strlen(uri_enc)-1);
        p=slash+1;
    }
    uri_encode(p,enc,sizeof(enc),1);
    strncat(uri_enc,enc,sizeof(uri_enc)-strlen(uri_enc)-1);

    char canonical_headers[1024];
    snprintf(canonical_headers, sizeof(canonical_headers),
             "host:%s\nx-amz-content-sha256:%s\nx-amz-copy-source:%s\nx-amz-date:%s\n",
             host, EMPTY_BODY_HASH, copy_source, amzdate);
    const char* signed_headers = "host;x-amz-content-sha256;x-amz-copy-source;x-amz-date";

    char auth[1024];
    sign_request(&ctx->cred, "PUT", uri_enc, "",
                 canonical_headers, signed_headers,
                 EMPTY_BODY_HASH, amzdate, datestamp, auth, sizeof(auth));

    wchar_t* whost2 = a2w(host);
    wchar_t* wpath2 = a2w(uri_enc);

    HINTERNET hConn = WinHttpConnect(ctx->hSession, whost2, INTERNET_DEFAULT_HTTPS_PORT, 0);
    free(whost2);
    if (!hConn) { free(wpath2); return 0; }

    HINTERNET hReq = WinHttpOpenRequest(hConn, L"PUT", wpath2, NULL,
                                         WINHTTP_NO_REFERER,
                                         WINHTTP_DEFAULT_ACCEPT_TYPES,
                                         WINHTTP_FLAG_SECURE);
    free(wpath2);
    if (!hReq) { WinHttpCloseHandle(hConn); return 0; }

    DWORD dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));

    char hdr[2048];
    wchar_t* wh;
    snprintf(hdr, sizeof(hdr), "x-amz-date: %s", amzdate);
    wh = a2w(hdr); WinHttpAddRequestHeaders(hReq, wh, -1L, WINHTTP_ADDREQ_FLAG_ADD); free(wh);
    snprintf(hdr, sizeof(hdr), "x-amz-content-sha256: %s", EMPTY_BODY_HASH);
    wh = a2w(hdr); WinHttpAddRequestHeaders(hReq, wh, -1L, WINHTTP_ADDREQ_FLAG_ADD); free(wh);
    snprintf(hdr, sizeof(hdr), "x-amz-copy-source: %s", copy_source);
    wh = a2w(hdr); WinHttpAddRequestHeaders(hReq, wh, -1L, WINHTTP_ADDREQ_FLAG_ADD); free(wh);
    snprintf(hdr, sizeof(hdr), "Authorization: %s", auth);
    wh = a2w(hdr); WinHttpAddRequestHeaders(hReq, wh, -1L, WINHTTP_ADDREQ_FLAG_ADD); free(wh);

    wh = a2w("Content-Length: 0");
    WinHttpAddRequestHeaders(hReq, wh, -1L, WINHTTP_ADDREQ_FLAG_ADD);
    free(wh);

    BOOL bok = WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0);
    if (bok) bok = WinHttpReceiveResponse(hReq, NULL);
    DWORD st = 0, sz2 = sizeof(DWORD);
    if (bok) WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                  WINHTTP_HEADER_NAME_BY_INDEX, &st, &sz2, WINHTTP_NO_HEADER_INDEX);
    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConn);
    return (st >= 200 && st < 300) ? 1 : 0;
}