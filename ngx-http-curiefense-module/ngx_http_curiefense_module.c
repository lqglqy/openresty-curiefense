#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#ifndef CURIEFENSE_DDEBUG
#define CURIEFENSE_DDEBUG 1
#endif
#include "ddebug.h"
#include "ngx_http_curiefense_common.h"


static void *ngx_http_curiefense_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_curiefense_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_curiefense_init(ngx_conf_t *cf);

/*
 * ngx_string's are not null-terminated in common case, so we need to convert
 * them into null-terminated ones before passing to ModSecurity
 */
ngx_inline char *ngx_str_to_char(ngx_str_t a, ngx_pool_t *p)
{
    char *str = NULL;

    if (a.len == 0) {
        return NULL;
    }

    str = ngx_pnalloc(p, a.len+1);
    if (str == NULL) {
        dd("failed to allocate memory to convert space ngx_string to C string");
        /* We already returned NULL for an empty string, so return -1 here to indicate allocation error */
        return (char *)-1;
    }
    ngx_memcpy(str, a.data, a.len);
    str[a.len] = '\0';

    return str;
}

char *ngx_http_curiefense_config_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) 
{
	ngx_http_curiefense_loc_conf_t *loc_conf = conf;
    ngx_str_t *values = cf->args->elts;
    if (cf->args->nelts > 1) {
        loc_conf->curiefense_config_path = values[1];
    }
    if (cf->args->nelts > 2) {
        loc_conf->curiefense_debug_level = ngx_atoi(values[2].data, values[2].len);
    } else {
        loc_conf->curiefense_debug_level = 3; // 0:debug 1:info 2: warn 3:error level
    }
	if (loc_conf->curiefense_config_path.len != NGX_CONF_UNSET_SIZE) {
        loc_conf->config = curiefense_stream_config_init(
                            loc_conf->curiefense_debug_level,
                            (char *) loc_conf->curiefense_config_path.data);
        if (loc_conf->config == NULL) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "Failed to initialize curiefense stream config");
            return NGX_CONF_ERROR;
        }
        ngx_log_error(NGX_LOG_INFO, cf->log, 0, "initialize curiefense stream config finish: %s",
                        (char *) loc_conf->curiefense_config_path.data);
        dd("curiefense init config from: %.*s\n",loc_conf->curiefense_config_path.len, (char*)loc_conf->curiefense_config_path.data);
    }

    return NGX_CONF_OK;
}

static ngx_command_t ngx_http_curiefense_commands[] = {
    { ngx_string("curiefense"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_curiefense_config_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_curiefense_loc_conf_t, curiefense_config_path),
      NULL },

    { ngx_string("curiefense_authority"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_curiefense_loc_conf_t, curiefense_authority),
      NULL },

    ngx_null_command
};

static ngx_http_module_t ngx_http_curiefense_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_curiefense_init,             /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_curiefense_create_loc_conf,  /* create location configuration */
    ngx_http_curiefense_merge_loc_conf    /* merge location configuration */
};

ngx_module_t ngx_http_curiefense_module = {
    NGX_MODULE_V1,
    &ngx_http_curiefense_module_ctx, /* module context */
    ngx_http_curiefense_commands,    /* module directives */
    NGX_HTTP_MODULE,                  /* module type */
    NULL,                             /* init master */
    NULL,                             /* init module */
    NULL,                             /* init process */
    NULL,                             /* init thread */
    NULL,                             /* exit thread */
    NULL,                             /* exit process */
    NULL,                             /* exit master */
    NGX_MODULE_V1_PADDING
};

static void *ngx_http_curiefense_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_curiefense_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_curiefense_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_str_null(&conf->curiefense_config_path);
    ngx_str_null(&conf->curiefense_authority);
    conf->curiefense_debug_level = NGX_CONF_UNSET_UINT;

    return conf;
}

static char *ngx_http_curiefense_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_curiefense_loc_conf_t *prev = parent;
    ngx_http_curiefense_loc_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->curiefense_config_path, prev->curiefense_config_path, "");
    ngx_conf_merge_str_value(conf->curiefense_authority, prev->curiefense_authority, "");
    ngx_conf_merge_uint_value(conf->curiefense_debug_level, prev->curiefense_debug_level, 0);

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_curiefense_init(ngx_conf_t *cf) {
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_handler_pt       *h;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_curiefense_rewrite_handler;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_curiefense_pre_access_handler;

    return NGX_OK;
}

void
ngx_http_curiefense_cleanup(void *data)
{
    ngx_http_curiefense_ctx_t *ctx = (ngx_http_curiefense_ctx_t *)data;
    if (ctx->cf_transaction) {
        dd("cleanup %p\n", ctx->cf_transaction);
        curiefense_stream_free(ctx->cf_transaction);
    }

}
ngx_inline ngx_http_curiefense_ctx_t *
ngx_http_curiefense_create_ctx(ngx_http_request_t *r)
{
    ngx_pool_cleanup_t                *cln;
    ngx_http_curiefense_ctx_t        *ctx;

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_curiefense_ctx_t));
    if (ctx == NULL)
    {
        dd("failed to allocate memory for the context.");
        return NULL;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_curiefense_module);

    cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_http_curiefense_ctx_t));
    if (cln == NULL)
    {
        dd("failed to create the Curiefense context cleanup");
        return NGX_CONF_ERROR;
    }
    cln->handler = ngx_http_curiefense_cleanup;
    cln->data = ctx;

    return ctx;
}