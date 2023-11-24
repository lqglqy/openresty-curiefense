#ifndef CURIEFENSE_DDEBUG
#define CURIEFENSE_DDEBUG 1
#endif
#include "ddebug.h"

#include "ngx_http_curiefense_common.h"

void
ngx_http_curiefense_request_read(ngx_http_request_t *r)
{
    ngx_http_curiefense_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_curiefense_module);

#if defined(nginx_version) && nginx_version >= 8011
    r->main->count--;
#endif

    if (ctx->waiting_more_body)
    {
        ctx->waiting_more_body = 0;
        r->write_event_handler = ngx_http_core_run_phases;
        ngx_http_core_run_phases(r);
    }
}

ngx_int_t
ngx_http_curiefense_get_raw_request_b64(ngx_http_request_t *r, ngx_int_t max_len, ngx_str_t *b64)
{
    u_char *buf, *p, *cur;
    ngx_int_t left;
    if (max_len <= 0) 
        return 0;
    
    buf= ngx_palloc(r->pool, max_len);
    if (!buf) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to alloc");
        return 0;
    }

    // request line
    left = max_len;
    p = cur = buf;
    p = ngx_snprintf(cur, left, "%V\r\n", &r->request_line);

    left -= (p - cur);
    cur = p;

    // headers
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
        p = ngx_snprintf(cur, left, "%V:%V\r\n", &data[i].key, &data[i].value);
        left -= (p - cur);
        cur = p;
        if (left <= 0) {
            break;
        }
    }


    // body
    if (left > 0) {
        p = ngx_snprintf(cur, left, "\r\n");
        left -= (p - cur);
        cur = p;
        ngx_chain_t *chain = r->request_body->bufs;

        /**
         * TODO: Speed up the analysis by sending chunk while they arrive.
         *
         * Notice that we are waiting for the full request body to
         * start to process it, it may not be necessary. We may send
         * the chunks to curiefense while nginx keep calling this
         * function.
         */

        if (r->request_body->temp_file != NULL) {
            ngx_str_t file_path = r->request_body->temp_file->file.name;
            const char *file_name = ngx_str_to_char(file_path, r->pool);
            if (file_name == (char*)-1) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            /*
             * Request body was saved to a file, probably we don't have a
             * copy of it in memory.
             */
            dd("request body inspection: file -- %s", file_name);

            // TODO: logging file

        } else {
            dd("logging request body in memory.");
        }

        while (chain)
        {
            u_char *data = chain->buf->pos;
            //p = ngx_snprintf(cur, left, "%.*s", , data);
            int len = (int)(chain->buf->last - data);
            if (len > left) 
                len = left;
            ngx_memcpy(cur, data, len);

            left -= len;
            cur += len;
            if (chain->buf->last_buf || left <= 0) {
                break;
            }
            chain = chain->next;

        } 
        p = cur;
    }

    ngx_str_t src;
    src.data = buf;
    src.len = p - buf;
    // base64 encode
    b64->len = ngx_base64_encoded_length(src.len);
    b64->data = ngx_palloc(r->pool, b64->len);
    if (b64->data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to alloc, 0x00000001");
        return 0;
    }
    
    ngx_encode_base64(b64, &src);
    return b64->len;
}

ngx_int_t
ngx_http_curiefense_attack_log(ngx_http_request_t *r, 
                            ngx_http_curiefense_ctx_t *ctx, 
                            dpi_curiefense_match_log_t *ml,
                            char *logstr)
{
    u_char *buf, *p, *cur;
    ngx_int_t left;
    ngx_str_t                 local_addr;
    u_char                    addr[NGX_SOCKADDR_STRLEN];

    ngx_http_curiefense_loc_conf_t *ccf;

    ccf = ngx_http_get_module_loc_conf(r, ngx_http_curiefense_module);
    if (ccf == NULL) {
        dd("Curiefense not config... returning");
        return NGX_DECLINED;
    }

    buf = ngx_palloc(r->pool, CF_ATTACK_LOG_MAX_LEN);
    if (!buf) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to alloc");
        return NGX_ERROR;
    }

    // dest ip
    local_addr.len = NGX_SOCKADDR_STRLEN;
    local_addr.data = addr;
    if (ngx_connection_local_sockaddr(r->connection, &local_addr, 0) != NGX_OK) {
        snprintf((char *)addr, sizeof(addr), "N/A");
        local_addr.len = 3;
    }
    int client_port = ngx_inet_get_port(r->connection->sockaddr);
    int server_port = ngx_inet_get_port(r->connection->local_sockaddr);

    left = CF_ATTACK_LOG_MAX_LEN - 1;
    p = cur = buf;
    p = ngx_snprintf(cur, left, "{"
		"\"timestamp\": %l,"
		"\"sip\": \"%V\","
		"\"sport\": \"%d\","
		"\"dip\": \"%V\","
		"\"dport\": \"%d\","
		"\"sid\": \"%V\"," // service id
		"\"rid\": \"%d\"," // rule id
		"\"rll\": \"%d\"," // risk level
		"\"act\": \"%d\"," // action
		"\"cat\": \"%s\"," // categroy
		"\"adc\": \"%s\",", // attack desc
		ngx_time(),
        &r->connection->addr_text,
        client_port,
        &local_addr,
        server_port,
        &ccf->curiefense_authority,
        ml->rule_id,
        ml->risk_level,
        ml->action,
        ml->category,
        logstr
	);
    left -= (p - cur);
	cur = p;

    ngx_str_t req_b64;
    ngx_int_t blen = ngx_http_curiefense_get_raw_request_b64(r, left, &req_b64);
    if (blen > 0){
        p = ngx_snprintf(cur, left, "\"rrt\": \"%V\"}", &req_b64); // raw request
    }

    ctx->attack_log.data = buf;
    ctx->attack_log.len = p - buf;

    return NGX_OK;
}

ngx_int_t
ngx_http_curiefense_pre_access_handler(ngx_http_request_t *r)
{
#if 1
    ngx_http_curiefense_ctx_t   *ctx;
    ngx_http_curiefense_loc_conf_t  *mcf;

    dd("catching a new _preaccess_ phase handler");

    mcf = ngx_http_get_module_loc_conf(r, ngx_http_curiefense_module);
    if (mcf == NULL || mcf->config == NULL)
    {
        dd("curiefense not enabled... returning");
        return NGX_DECLINED;
    }
    /*
     * FIXME:
     * In order to perform some tests, let's accept everything.
     *
    if (r->method != NGX_HTTP_GET &&
        r->method != NGX_HTTP_POST && r->method != NGX_HTTP_HEAD) {
        dd("curiefense is not ready to deal with anything different from " \
            "POST, GET or HEAD");
        return NGX_DECLINED;
    }
    */

    ctx = ngx_http_get_module_ctx(r, ngx_http_curiefense_module);

    dd("recovering ctx: %p", ctx);

    if (ctx == NULL)
    {
        dd("ctx is null; Nothing we can do, returning an error.");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ctx->waiting_more_body == 1)
    {
        dd("waiting for more data before proceed. / count: %d",
            r->main->count);

        return NGX_DONE;
    }

    if (ctx->body_requested == 0)
    {
        ngx_int_t rc = NGX_OK;

        ctx->body_requested = 1;

        dd("asking for the request body, if any. Count: %d",
            r->main->count);
        /**
         * TODO: Check if there is any benefit to use request_body_in_single_buf set to 1.
         *
         *       saw some module using this request_body_in_single_buf
         *       but not sure what exactly it does, same for the others options below.
         *
         * r->request_body_in_single_buf = 1;
         */
        r->request_body_in_single_buf = 1;
        r->request_body_in_persistent_file = 1;
        if (!r->request_body_in_file_only) {
            // If the above condition fails, then the flag below will have been
            // set correctly elsewhere. We need to set the flag here for other
            // conditions (client_body_in_file_only not used but
            // client_body_buffer_size is)
            r->request_body_in_clean_file = 1;
        }

        rc = ngx_http_read_client_request_body(r,
            ngx_http_curiefense_request_read);
        if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
#if (nginx_version < 1002006) ||                                             \
    (nginx_version >= 1003000 && nginx_version < 1003009)
            r->main->count--;
#endif

            return rc;
        }
        if (rc == NGX_AGAIN)
        {
            dd("nginx is asking us to wait for more data.");

            ctx->waiting_more_body = 1;
            return NGX_DONE;
        }
    }

    if (ctx->waiting_more_body == 0)
    {
        int already_inspected = 0;

        dd("request body is ready to be processed");

        r->write_event_handler = ngx_http_core_run_phases;

        ngx_chain_t *chain = r->request_body->bufs;

        /**
         * TODO: Speed up the analysis by sending chunk while they arrive.
         *
         * Notice that we are waiting for the full request body to
         * start to process it, it may not be necessary. We may send
         * the chunks to curiefense while nginx keep calling this
         * function.
         */

        if (r->request_body->temp_file != NULL) {
            ngx_str_t file_path = r->request_body->temp_file->file.name;
            const char *file_name = ngx_str_to_char(file_path, r->pool);
            if (file_name == (char*)-1) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            /*
             * Request body was saved to a file, probably we don't have a
             * copy of it in memory.
             */
            dd("request body inspection: file -- %s", file_name);

            // TODO: Check file
            //msc_request_body_from_file(ctx->modsec_transaction, file_name);

            already_inspected = 1;
        } else {
            dd("inspection request body in memory.");
        }

        while (chain && !already_inspected)
        {
            u_char *data = chain->buf->pos;
            CFStreamStatus status = curiefense_stream_add_body(&ctx->cf_transaction, 
                               data, chain->buf->last - data);
            if (status == CFSError) {
                dd("Failed to add body: %d\n", status);
            }

            if (chain->buf->last_buf) {
                break;
            }
            chain = chain->next;

        }

        /**
         * At this point, all the request body was sent to curiefense
         * and we want to make sure that all the request body inspection
         * happened; consequently we have to check if curiefense have
         * returned any kind of intervention.
         */

/* XXX: once more -- is body can be modified ?  content-length need to be adjusted ? */
        CFResult *out = NULL;
        CFProgress cfp = curiefense_stream_exec_sync(mcf->config, ctx->cf_transaction, &out);
        ctx->cf_transaction = NULL;
        if (cfp) {
            dd("Failed to execute!\n");
            return NGX_DECLINED;
        }

        uintptr_t len = 0;
        dpi_curiefense_match_log_t m;
        m.action = 0;
        
        char *logstr = curiefense_cfr_log_dosec(out, &len, &m.action, &m.rule_id, &m.risk_level, m.category);
        
        if (logstr && (m.action == CF_ACTION_BLOCK || m.action == CF_ACTION_MONITOR)) {
        //if (logstr) {
            // TODO: send log to agent by udp
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "cfr_log:%s, action: %d, rule_id: %d, risk_level: %d, category: %s\n", 
                                               logstr, m.action, m.rule_id, m.risk_level, m.category);
            dd("cfr_log:%s, action: %d, rule_id: %d, risk_level: %d, category: %s\n", 
                                               logstr, m.action, m.rule_id, m.risk_level, m.category);
            ngx_http_curiefense_attack_log(r, ctx, &m, logstr);
            curiefense_str_free(logstr);
        }
        if (m.action == CF_ACTION_BLOCK) {
            // TODO: use block status code
            return 403;
        }

        dd("execute end!!\n");
    }

    dd("Nothing to add on the body inspection, reclaiming a NGX_DECLINED");
#endif
    return NGX_DECLINED;
}
