#ifndef _NGX_HTTP_CURIEFENSE_COMMON_H_
#define _NGX_HTTP_CURIEFENSE_COMMON_H_
#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "curiefense_ffi.h"

typedef struct {
    struct CFStreamHandle *cf_transaction;
    unsigned waiting_more_body:1;
    unsigned body_requested:1;
} ngx_http_curiefense_ctx_t;

typedef struct {
    ngx_str_t  curiefense_config_path;
    ngx_str_t  curiefense_authority;
    ngx_uint_t curiefense_debug_level;
    struct CFStreamConfig *config;
} ngx_http_curiefense_loc_conf_t;

typedef struct dpi_curiefense_match_log_ {
    uint32_t rule_id;
    uint8_t risk_level;
    uint8_t action;
#define MAX_CATEGORY_LEN 16
    char category[MAX_CATEGORY_LEN];
} dpi_curiefense_match_log_t;

extern ngx_module_t ngx_http_curiefense_module;

ngx_http_curiefense_ctx_t *ngx_http_curiefense_create_ctx(ngx_http_request_t *r);
ngx_int_t ngx_http_curiefense_rewrite_handler(ngx_http_request_t *r);
ngx_int_t ngx_http_curiefense_pre_access_handler(ngx_http_request_t *r);
char *ngx_str_to_char(ngx_str_t a, ngx_pool_t *p);
#endif