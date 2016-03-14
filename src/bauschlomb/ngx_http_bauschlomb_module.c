/*
 * ngx_http_bauschlomb_module.cpp
 *
 *  Created on: 2015年5月30日
 *      Author: zhangdaoqiang
 */

#include "../bauschlomb/ngx_http_bauschlomb_module.h"

typedef struct
{
	ngx_str_t server_mac;
} ngx_http_bauschlomb_loc_conf_t;

static ngx_int_t ngx_http_bauschlomb_init(ngx_conf_t *cf);

static void *ngx_http_bauschlomb_create_loc_conf(ngx_conf_t *cf);

static char *ngx_http_bauschlomb_param(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);

static ngx_command_t ngx_http_bauschlomb_commands[] = {
		{
			ngx_string("server_mac"),
			NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
			ngx_http_bauschlomb_param,
			NGX_HTTP_LOC_CONF_OFFSET,
			offsetof(ngx_http_bauschlomb_loc_conf_t, server_mac),
			NULL },

        ngx_null_command
};

static ngx_http_module_t ngx_http_bauschlomb_module_ctx = {
        NULL,                          /* preconfiguration */
        ngx_http_bauschlomb_init,           /* postconfiguration */

        NULL,                          /* create main configuration */
        NULL,                          /* init main configuration */

        NULL,                          /* create server configuration */
        NULL,                          /* merge server configuration */

        ngx_http_bauschlomb_create_loc_conf, /* create location configuration */
        NULL                            /* merge location configuration */
};

ngx_module_t ngx_http_bauschlomb_module = {
        NGX_MODULE_V1,
        &ngx_http_bauschlomb_module_ctx,    /* module context */
        ngx_http_bauschlomb_commands,       /* module directives */
        NGX_HTTP_MODULE,               /* module type */
        NULL,                          /* init master */
        NULL,                          /* init module */
        NULL,                          /* init process */
        NULL,                          /* init thread */
        NULL,                          /* exit thread */
        NULL,                          /* exit process */
        NULL,                          /* exit master */
        NGX_MODULE_V1_PADDING
};

static ngx_str_t serverMac;

static const int IP_COUNT = 256;
static int iosClient[256];

static ngx_int_t
ngx_http_bauschlomb_handler(ngx_http_request_t *r)
{
	ngx_int_t    rc;
	ngx_buf_t   *b;
	ngx_chain_t  out;
	u_char *captiveNetworkBody = (u_char*)"!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2//EN\"><HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>";
	ngx_uint_t content_length = 0;
	u_char *captiveFromIos = NULL;
	u_char *ua = NULL;
	ngx_str_t ip;
	ngx_uint_t hash;
	int ipIndex;
	u_char *welcomePage = NULL;

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bauschlomb,>>uri##%s",r->uri.data);


	/* we response to 'GET' and 'HEAD' requests only */
	if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
			return NGX_HTTP_NOT_ALLOWED;
	}

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bauschlomb,##before discard request body");
	rc = ngx_http_discard_request_body(r);
	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bauschlomb,##after discard request body");
	if (rc != NGX_OK) {
		return rc;
	}

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bauschlomb,##check welcome");
	if(r->uri.data){
		welcomePage = (u_char*)ngx_strstr(r->uri.data, "/welcome");
	}
	if(welcomePage){
		return NGX_DECLINED;
	}

	ip = r->connection->addr_text;
	hash = ngx_hash_key(ip.data,ip.len);
	ipIndex = hash & (IP_COUNT -1);
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bauschlomb,##ipIndex=%d", ipIndex);

	if(r->headers_in.user_agent){
		ua = r->headers_in.user_agent->value.data;
	}
	if(ua){
		captiveFromIos = (u_char*)ngx_strstr(ua, "CaptiveNetworkSupport");
	}

	if(!captiveFromIos){
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bauschlomb,##not CaptiveNetworkSupport");
		//非探测请求,放行,由后续模块处理
		if((u_char*)ngx_strstr(ua, "bsldata") ||
				(u_char*)ngx_strstr(ua, "data") ||
				(u_char*)ngx_strstr(ua, "ext") ||
				(u_char*)ngx_strstr(ua, "welcome")){
			return NGX_DECLINED;
		}
		return NGX_DECLINED;
	}else{
		//ios 探测
		iosClient[ipIndex] += 1;
		int captive = iosClient[ipIndex];
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "bauschlomb,##captive=%d",captive);
		if(captive % 2 == 1){
			return NGX_DECLINED;
		}

		content_length = ngx_strlen(captiveNetworkBody);
	}

	/* set the 'Content-type' header */
	/*
	 *r->headers_out.content_type.len = sizeof("text/html") - 1;
	 *r->headers_out.content_type.data = (u_char *)"text/html";
	 */
	ngx_str_set(&r->headers_out.content_type, "text/html");

	/* send the header only, if the request type is http 'HEAD' */
	if (r->method == NGX_HTTP_HEAD) {
			r->headers_out.status = NGX_HTTP_OK;
			r->headers_out.content_length_n = content_length;

			return ngx_http_send_header(r);
	}

	/* allocate a buffer for your response body */
	b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
	if (b == NULL) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	/* attach this buffer to the buffer chain */
	out.buf = b;
	out.next = NULL;

	/* adjust the pointers of the buffer */
	b->pos = (u_char*)captiveNetworkBody;
	b->last = ((u_char*)captiveNetworkBody) + content_length;
	b->memory = 1;    /* this buffer is in memory */
	b->last_buf = 1;  /* this is the last buffer in the buffer chain */

	/* set the status line */
	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = content_length;

	/* send the headers of your response */
	rc = ngx_http_send_header(r);

	if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
			return rc;
	}

	/* send the buffer chain of your response */
	return ngx_http_output_filter(r, &out);
}

static void *ngx_http_bauschlomb_create_loc_conf(ngx_conf_t *cf)
{
        ngx_http_bauschlomb_loc_conf_t* local_conf = NULL;
        local_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_bauschlomb_loc_conf_t));
        if (local_conf == NULL)
        {
                return NULL;
        }

        ngx_str_null(&local_conf->server_mac);

        return local_conf;
}

/*
static char *ngx_http_bauschlomb_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
        ngx_http_bauschlomb_loc_conf_t* prev = parent;
        ngx_http_bauschlomb_loc_conf_t* conf = child;

        ngx_conf_merge_value(conf->bauschlomb, prev->bauschlomb, 0);

        return NGX_CONF_OK;
}*/

static ngx_int_t
ngx_http_bauschlomb_init(ngx_conf_t *cf)
{
        ngx_http_handler_pt        *h;
        ngx_http_core_main_conf_t  *cmcf;

        cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

        h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
        if (h == NULL) {
                return NGX_ERROR;
        }

        *h = ngx_http_bauschlomb_handler;

        return NGX_OK;
}

static char *ngx_http_bauschlomb_param(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf)
{
        ngx_http_bauschlomb_loc_conf_t* local_conf;
        local_conf = conf;
        char* rv = NULL;

        rv = ngx_conf_set_str_slot(cf, cmd, conf);

        serverMac = local_conf->server_mac;
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "server_mac###%s", serverMac.data);
        return rv;
}
