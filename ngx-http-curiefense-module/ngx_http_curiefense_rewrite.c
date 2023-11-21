#ifndef CURIEFENSE_DDEBUG
#define CURIEFENSE_DDEBUG 1
#endif

#include "ddebug.h"
#include "ngx_http_curiefense_common.h"

ngx_int_t
ngx_http_curiefense_rewrite_handler(ngx_http_request_t *r)
{
    ngx_http_curiefense_ctx_t *ctx;
    ngx_http_curiefense_loc_conf_t *ccf;

    ccf = ngx_http_get_module_loc_conf(r, ngx_http_curiefense_module);
    if (ccf == NULL) {
        dd("Curiefense not config... returning");
        return NGX_DECLINED;
    }

    dd("catching a new _rewrite_ phase handler");
    ctx = ngx_http_get_module_ctx(r, ngx_http_curiefense_module);
    dd("recovering ctx: %p", ctx);
    if (ctx == NULL) {
        ngx_connection_t *conn = r->connection;
        ctx = ngx_http_curiefense_create_ctx(r);

        dd("ctx was NULL, creating new context: %p", ctx);

        if (ctx == NULL) {
            dd("ctx still null; Nothing we can do, returning an error.");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        const char *client_addr = ngx_str_to_char(conn->addr_text, r->pool);
        if (client_addr == (char *)-1) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        struct CFHashmap *hm = cf_hashmap_new();
        if (!hm) {
            dd("create cf hashmap failed!!! return!");
            return NGX_DECLINED;
        }
        cf_hashmap_insert(hm, "method", 6, (const char *)r->method_name.data, r->method_name.len);
        cf_hashmap_insert(hm, "path", 4, (const char *)r->unparsed_uri.data, r->unparsed_uri.len);
        cf_hashmap_insert(hm, "authority", 9, (const char*)ccf->curiefense_authority.data, ccf->curiefense_authority.len);
        enum CFStreamStatus status = 0;
        ctx->cf_transaction = curiefense_stream_start(ccf->config, hm, client_addr, &status);
        if (ctx->cf_transaction == NULL) {
            dd("create cf transaction failed!!! return!");
            return NGX_DECLINED;
        } 

        ngx_list_part_t *part = &r->headers_in.headers.part;
        ngx_table_elt_t *data = part->elts;
        ngx_uint_t i = 0;
        for (i = 0 ; /* void */ ; i++) {
            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                data = part->elts;
                i = 0;
            }

            /**
             * By using u_char (utf8_t) I believe nginx is hoping to deal
             * with utf8 strings.
             * Casting those into to unsigned char * in order to pass
             * it to CURIEFENSE, it will handle with those later.
             *
             */

            dd("Adding request header: %.*s with value %.*s", (int)data[i].key.len, data[i].key.data, (int) data[i].value.len, data[i].value.data);
            CFStreamStatus status = curiefense_stream_add_header(&ctx->cf_transaction, 
                                    (const char *) data[i].key.data,
                                    data[i].key.len,
                                    (const char *) data[i].value.data,
                                    data[i].value.len);
            if (status == CFSError) {
                dd("Failed to add header: %d\n", status);
                return NGX_DECLINED;
            }
        }
    }
    return NGX_DECLINED;
}