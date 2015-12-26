/**
 * substitute cdn urls for some specific static urls
 *
 * one of nginx modules I developed
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>

#include <ctype.h>
#include <string.h>


// max lengths for the buffers
// holding a tag, an attribute or a URL respectively
#define MAX_TAG_LEN 16
#define MAX_ATTR_LEN 16
#define MAX_URL_LEN 1024

// for which type of static files (pic, css, js)
// this module works
#define CDN_TYPE_NIL 0
#define CDN_TYPE_PIC 1
#define CDN_TYPE_CSS 2
#define CDN_TYPE_JS 3


// location config of this module
typedef struct {
    ngx_array_t *attrs;
    ngx_hash_t attrs_hash;

    ngx_str_t cdn_url_prefix_pic;
    ngx_str_t cdn_url_prefix_css;
    ngx_str_t cdn_url_prefix_js;

    ngx_array_t *reserved_domains;

    // TODO
    ngx_hash_t mime_types;
    ngx_array_t *mime_types_keys;

    // TODO
    ngx_hash_t file_exts;
    ngx_array_t *file_exts_keys;
} sub_url_loc_conf_t;


typedef enum {
    state_normal = 0,
    state_lt_hit,
    state_tag_middle,
    state_tag_captured,
    state_attr_middle,
    state_attr_restart,
    state_attr_captured,
    state_url_start,
    state_url_middle
} sub_url_state_e;


// context data of this module
typedef struct {
    u_char *pos;

    ngx_buf_t *buf;

    ngx_chain_t *in;
    ngx_chain_t *out;
    ngx_chain_t **last_out;
    ngx_chain_t *free;
    ngx_chain_t *busy;

    ngx_uint_t state;

    ngx_int_t eq_hit;

    ngx_str_t tag;
    ngx_str_t attr;
    ngx_str_t target_attr;
    ngx_str_t url;

    u_char quot;
} sub_url_ctx_t;


static ngx_inline ngx_chain_t *sub_url_new_chain_buf(ngx_http_request_t *r,
                                                     sub_url_ctx_t *ctx);

static char *sub_url_set_attrs(ngx_conf_t *cf, ngx_command_t *cmd,
                               void *conf);
static char *sub_url_set_attr(ngx_conf_t *cf, ngx_command_t *dummy,
                              void *conf);

static char *sub_url_reserve_domains(ngx_conf_t *cf,
                                     ngx_command_t *cmd, void *conf);

static ngx_uint_t sub_url_hash_name(ngx_http_request_t *r, ngx_str_t *name);

static void sub_url_md5(u_char *data, size_t len, u_char result[32]);
static ngx_str_t *sub_url_escape_url(ngx_pool_t *pool,
                                     u_char *url, size_t len);

static ngx_int_t sub_url_domain_equals(u_char *d1, size_t n1,
                                       u_char *d2, size_t n2);
static ngx_str_t *sub_url_cdn_url(ngx_http_request_t *r, u_char *url,
                                  size_t len, ngx_uint_t *cdn_type);

static ngx_int_t sub_url_output(ngx_http_request_t *r,
                                sub_url_ctx_t *ctx);

static ngx_int_t sub_url_parse_state_normal(ngx_http_request_t *r,
                                            sub_url_ctx_t *ctx);
static ngx_int_t sub_url_parse_state_lt_hit(ngx_http_request_t *r,
                                            sub_url_ctx_t *ctx);
static ngx_int_t sub_url_parse_state_tag_middle(ngx_http_request_t *r,
                                                sub_url_ctx_t *ctx);
static ngx_int_t sub_url_parse_state_tag_captured(ngx_http_request_t *r,
                                                  sub_url_ctx_t *ctx);
static ngx_int_t sub_url_parse_state_attr_middle(ngx_http_request_t *r,
                                                 sub_url_ctx_t *ctx);
static ngx_int_t sub_url_parse_state_attr_restart(ngx_http_request_t *r,
                                                  sub_url_ctx_t *ctx);
static ngx_int_t sub_url_parse_state_attr_captured(ngx_http_request_t *r,
                                                   sub_url_ctx_t *ctx);
static ngx_int_t sub_url_parse_state_url_start(ngx_http_request_t *r,
                                               sub_url_ctx_t *ctx);
static ngx_int_t sub_url_parse_state_url_middle(ngx_http_request_t *r,
                                                sub_url_ctx_t *ctx);

static ngx_int_t sub_url_header_filter(ngx_http_request_t *r);
static ngx_int_t sub_url_body_filter(ngx_http_request_t *r, ngx_chain_t *in);

static ngx_int_t sub_url_filter_init(ngx_conf_t *cf);

static void *sub_url_create_loc_conf(ngx_conf_t *cf);
static char *sub_url_merge_loc_conf(ngx_conf_t *cf,
                                    void *parent, void *child);


static ngx_str_t sub_url_default_file_exts[] = {
    ngx_string("jpg"),
    ngx_null_string
};


#if 0
static ngx_str_t sub_url_src_attr = ngx_string("src");
static ngx_str_t sub_url_href_attr = ngx_string("href");
#endif

// this module needs explicit config
static ngx_hash_key_t sub_url_default_attrs[] = {
#if 0
    { ngx_string("img"), 0, &sub_url_src_attr },
    { ngx_string("link"), 0, &sub_url_href_attr },
#endif
    { ngx_null_string, 0, NULL }
};


static ngx_command_t sub_url_filter_commands[] = {
    { ngx_string("sub_url_attrs"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
                        |NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      sub_url_set_attrs,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("sub_url_cdn_prefix_pic"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(sub_url_loc_conf_t, cdn_url_prefix_pic),
      NULL },

    { ngx_string("sub_url_cdn_prefix_css"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(sub_url_loc_conf_t, cdn_url_prefix_css),
      NULL },

    { ngx_string("sub_url_cdn_prefix_js"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(sub_url_loc_conf_t, cdn_url_prefix_js),
      NULL },

    { ngx_string("sub_url_reserved_domains"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      sub_url_reserve_domains,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    // TODO
    { ngx_string("sub_url_mime_types"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_types_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(sub_url_loc_conf_t, mime_types_keys),
      &ngx_http_html_default_types[0] },

    // TODO & FIXME
    { ngx_string("sub_url_file_exts"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_types_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(sub_url_loc_conf_t, file_exts_keys),
      &sub_url_default_file_exts[0] },

    ngx_null_command
};


static ngx_http_module_t sub_url_filter_module_ctx = {
    NULL,                    /* preconfiguration */
    sub_url_filter_init,     /* postconfiguration */

    NULL,                    /* create main configuration */
    NULL,                    /* init main configuration */

    NULL,                    /* create server configuration */
    NULL,                    /* merge server configuration */

    sub_url_create_loc_conf, /* create location configuration */
    sub_url_merge_loc_conf   /* merge location configuration */
};


ngx_module_t sub_url_filter_module = {
    NGX_MODULE_V1,
    &sub_url_filter_module_ctx, /* module context */
    sub_url_filter_commands,    /* module directives */
    NGX_HTTP_MODULE,            /* module type */
    NULL,                       /* init master */
    NULL,                       /* init module */
    NULL,                       /* init process */
    NULL,                       /* init thread */
    NULL,                       /* exit thread */
    NULL,                       /* exit process */
    NULL,                       /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt ngx_http_next_body_filter;


// retrieve free buf from module's ctx or pool for this request
static ngx_inline ngx_chain_t *
sub_url_new_chain_buf(ngx_http_request_t *r, sub_url_ctx_t *ctx)
{
    ngx_buf_t *b;
    ngx_chain_t *cl;

    if (ctx->free) {
        cl = ctx->free;
        ctx->free = ctx->free->next;
        b = cl->buf;
    } else {
        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            return NULL;
        }

        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NULL;
        }

        cl->buf = b;
    }

    return cl;
}


static char *
sub_url_set_attrs(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    sub_url_loc_conf_t *sulcf = conf;

    char *rv;
    ngx_conf_t save;

    if (sulcf->attrs == NULL) {
        sulcf->attrs = ngx_array_create(cf->pool, 16, sizeof(ngx_hash_key_t));
        if (sulcf->attrs == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    save = *cf;

    cf->handler = sub_url_set_attr;
    cf->handler_conf = conf;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    return rv;
}


static char *
sub_url_set_attr(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
    sub_url_loc_conf_t *sulcf = conf;

    ngx_str_t *value, *attr_name, *old;
    ngx_uint_t i, n, hash;
    ngx_hash_key_t *attr;

    value = cf->args->elts;

    attr_name = ngx_palloc(cf->pool, sizeof(ngx_str_t));
    if (attr_name == NULL) {
        return NGX_CONF_ERROR;
    }

    *attr_name = value[0];

    for (i = 1; i < cf->args->nelts; i++) {
        hash = ngx_hash_strlow(value[i].data, value[i].data, value[i].len);

        attr = sulcf->attrs->elts;
        for (n = 0; n < sulcf->attrs->nelts; n++) {
            if (ngx_strcmp(value[i].data, attr[n].key.data) == 0) {
                old = attr[n].value;
                attr[n].value = attr_name;

                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "duplicate tag \"%V\", "
                                   "attr name: \"%V\", "
                                   "previous attr name: \"%V\"",
                                   &value[i], attr_name, old);
                goto next;
            }
        }

        attr = ngx_array_push(sulcf->attrs);
        if (attr == NULL) {
            return NGX_CONF_ERROR;
        }

        attr->key = value[i];
        attr->key_hash = hash;
        attr->value = attr_name;

    next:
        continue;
    }

    return NGX_CONF_OK;
}


// URLs with these domains won't be processed
static char *
sub_url_reserve_domains(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    sub_url_loc_conf_t *sulcf = conf;

    ngx_str_t *value, *domain;
    ngx_uint_t i;

    value = cf->args->elts;

    // XXX
    if (cf->args->nelts > 1) {
        sulcf->reserved_domains = ngx_array_create(cf->pool,
                                                   4, sizeof(ngx_str_t));
        if (sulcf->reserved_domains == NULL) {
            return NGX_CONF_ERROR;
        }
    } else {
        return NGX_CONF_ERROR;
    }

    for (i = 1; i < cf->args->nelts; i++) {
        domain = ngx_array_push(sulcf->reserved_domains);
        if (domain == NULL) {
            return NGX_CONF_ERROR;
        }

        *domain = value[i];
    }

    return NGX_CONF_OK;
}


static ngx_uint_t
sub_url_hash_name(ngx_http_request_t *r, ngx_str_t *name)
{
    u_char c, *nm;
    ngx_uint_t i, hash;

    hash = 0;

    for (i = 0; i < name->len; i++) {
        c = name->data[i];

        if (c >= 'A' && c <= 'Z') {
            nm = ngx_pnalloc(r->pool, name->len);
            if (nm == NULL) {
                return 0;
            }

            hash = ngx_hash_strlow(nm, name->data, name->len);

            break;
        }

        hash = ngx_hash(hash, c);
    }

    return hash;
}


static void
sub_url_md5(u_char *data, size_t len, u_char result[32])
{
    // XXX
    // static ngx_md5_t md5;
    ngx_md5_t md5;
    u_char buf[16];

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, data, len);
    ngx_md5_final(buf, &md5);

    ngx_hex_dump(result, buf, 32);
}


// URL encoding
static ngx_str_t *
sub_url_escape_url(ngx_pool_t *pool, u_char *url, size_t len)
{
    uintptr_t el;
    ngx_str_t *escaped;

    el = ngx_escape_uri(NULL, url, len, NGX_ESCAPE_URI_COMPONENT);

    escaped = ngx_palloc(pool, sizeof(ngx_str_t));
    if (escaped == NULL) {
        return NULL;
    }

    escaped->len = el * 2 + len;

    escaped->data = ngx_pnalloc(pool, escaped->len);

    ngx_escape_uri(escaped->data, url, len, NGX_ESCAPE_URI_COMPONENT);

    return escaped;
}


#define SK_PREFIX "MgaikyYOlTNq4IGAOW65qspUmZdBbiRc"
#define SK_SUFFIX ")a(*x1-&!x@$dwa#%^x&*()#@D$Ax%IR$(!K3@d"


static ngx_int_t
sub_url_domain_equals(u_char *d1, size_t n1, u_char *d2, size_t n2)
{
    size_t n;

    if (n1 > n2) {
        n = n2;
        d1 += (n1 - n2);

        if (*(d1 - 1) != '.') {
            return 1;
        }
    } else if (n1 < n2) {
        n = n1;
        d2 += (n2 - n1);

        if (*(d2 - 1) != '.') {
            return -1;
        }
    } else {
        n = n1;
    }

    return strncasecmp(d1, d2, n);
}


// transform to CDN URL
static ngx_str_t *
sub_url_cdn_url(ngx_http_request_t *r, u_char *url, size_t len,
                ngx_uint_t *cdn_type)
{
    size_t i, j, n, start;
    ngx_str_t srv, *cdn_url, *escaped, *domains, *prefix;
    ngx_http_core_srv_conf_t  *cscf;
    sub_url_loc_conf_t *sulcf;
    u_char sign[32], *temp;
    ngx_int_t dot = 0;

    i = 0;

    while (isspace(url[i])) {
        i++;
    }

    // src="../a.jpg" or src="./a.jpg"
    // added on 20140910
    if (url[i] == '.') {
        *cdn_type = CDN_TYPE_NIL;
        return NULL;
    }

    if (ngx_strncasecmp(&url[i], "http://", sizeof("http://") - 1) == 0) {
        i += sizeof("http://") - 1;
    } else if (ngx_strncasecmp(&url[i], "https://",
                               sizeof("https://") - 1) == 0) {
        i += sizeof("https://") - 1;
    }

    start = i;

    do {
        if (url[i] == '.') {
            dot++;
        }

        if (url[i] == '/') {
            break;
        }

        i++;
    } while (i < len);

    // a single file name without path components
    if (i == len) {
        *cdn_type = CDN_TYPE_NIL;
        return NULL;
    }

    if (dot == 0) {
        *cdn_type = CDN_TYPE_NIL;
        return NULL;
    }

    if (r->headers_in.server.len) {
        srv.len = r->headers_in.server.len;
        srv.data = r->headers_in.server.data;
    } else {
        cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

        srv.len = cscf->server_name.len;
        srv.data = cscf->server_name.data;
    }

    sulcf = ngx_http_get_module_loc_conf(r, sub_url_filter_module);
    if (sulcf == NULL) {
        return NULL;
    }

    j = len - 1;

    while (isspace(url[j])) {
        j--;
    }

    n = j;

    while (j > 0) {
        if (url[j--] == '?') {
            break;
        }
    }

    if (j == 0) {
        j = n;
    }

    if (url[j] == 's') {
        switch (url[j - 1]) {
        case 'j':
            *cdn_type = CDN_TYPE_JS;
            prefix = &sulcf->cdn_url_prefix_js;
            break;

        case 's':
            if (url[j - 2] == 'c') {
                *cdn_type = CDN_TYPE_CSS;
                prefix = &sulcf->cdn_url_prefix_css;
                break;
            }

        default:
            *cdn_type = CDN_TYPE_PIC;
            prefix = &sulcf->cdn_url_prefix_pic;
            break;
        }
    } else {
        *cdn_type = CDN_TYPE_PIC;
        prefix = &sulcf->cdn_url_prefix_pic;
    }

    if (sulcf->reserved_domains) {
        domains = sulcf->reserved_domains->elts;

        for (n = 0; n < sulcf->reserved_domains->nelts; n++) {
            if (i - start >= domains[n].len
                && sub_url_domain_equals(&url[start], i - start,
                                         domains[n].data, domains[n].len) == 0)
            {
                *cdn_type = CDN_TYPE_NIL;
                return NULL;
            }
        }
    }

#if 1
    if (i - start == srv.len) {
        if (ngx_strncasecmp(srv.data, &url[start], srv.len) == 0) {
            *cdn_type = CDN_TYPE_NIL;
            return NULL;
        }
    } else if (i - start > srv.len) {
        if (ngx_strncasecmp(srv.data, url + i - srv.len, srv.len) == 0) {
            *cdn_type = CDN_TYPE_NIL;
            return NULL;
        }
    }
#endif

    n = sizeof(SK_PREFIX) - 1 + len + sizeof(SK_SUFFIX) - 1;

    temp = ngx_pnalloc(r->pool, n);
    if (temp == NULL) {
        return NULL;
    }

    ngx_memcpy(temp, SK_PREFIX, sizeof(SK_PREFIX) - 1);
    ngx_memcpy(temp + sizeof(SK_PREFIX) - 1, url, len);
    ngx_memcpy(temp + sizeof(SK_PREFIX) - 1 + len,
               SK_SUFFIX, sizeof(SK_SUFFIX) - 1);

    sub_url_md5(temp, n, sign);

    escaped = sub_url_escape_url(r->pool, url, len);
    if (escaped == NULL) {
        return NULL;
    }

    cdn_url = ngx_palloc(r->pool, sizeof(ngx_str_t));
    if (cdn_url == NULL) {
        return NULL;
    }

    cdn_url->len = prefix->len + escaped->len + sizeof("&sign=") - 1 + 32;

    cdn_url->data = ngx_pnalloc(r->pool, cdn_url->len);
    if (cdn_url->data == NULL) {
        return NULL;
    }

    // XXX
    ngx_memcpy(cdn_url->data, prefix->data, prefix->len);
    ngx_memcpy(cdn_url->data + prefix->len, escaped->data, escaped->len);
    ngx_memcpy(cdn_url->data + prefix->len + escaped->len,
               "&sign=", sizeof("&sign=") - 1);
    ngx_memcpy(cdn_url->data + prefix->len + escaped->len
               + sizeof("&sign=") - 1, sign, 32);

    return cdn_url;
}


static ngx_int_t
sub_url_output(ngx_http_request_t *r, sub_url_ctx_t *ctx)
{
    ngx_int_t rc;
    ngx_buf_t *b;
    ngx_chain_t *cl;

#if 1
    b = NULL;
    for (cl = ctx->out; cl; cl = cl->next) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "sub url out: %p %p", cl->buf, cl->buf->pos);
        if (cl->buf == b) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "the same buf was used in sub url");
            ngx_debug_point();
            return NGX_ERROR;
        }
        b = cl->buf;
    }
#endif

    rc = ngx_http_next_body_filter(r, ctx->out);

    if (ctx->busy == NULL) {
        ctx->busy = ctx->out;
    } else {
        for (cl = ctx->busy; cl->next; cl = cl->next) { /* void */ }
        cl->next = ctx->out;
    }

    ctx->out = NULL;
    ctx->last_out = &ctx->out;

    while (ctx->busy) {
        cl = ctx->busy;
        b = cl->buf;

        if (ngx_buf_size(b) != 0) {
            break;
        }

        if (b->shadow) {
            b->shadow->pos = b->shadow->last;
        }

        ctx->busy = cl->next;

        if (ngx_buf_in_memory(b) || b->in_file) {
            /* add data bufs only to the free buf chain */

            cl->next = ctx->free;
            ctx->free = cl;
        }
    }

    if (ctx->in || ctx->buf) {
        r->buffered |= NGX_HTTP_SUB_BUFFERED;
    } else {
        r->buffered &= ~NGX_HTTP_SUB_BUFFERED;
    }

    return rc;
}


static ngx_int_t
sub_url_parse_state_normal(ngx_http_request_t *r, sub_url_ctx_t *ctx)
{
    u_char *p = ctx->pos;
    ngx_chain_t *cl;

    ctx->tag.len = 0;
    ctx->attr.len = 0;
    ctx->target_attr.len = 0;
    ctx->url.len = 0;

    ctx->quot = '?';
    ctx->eq_hit = 0;

    // look for '<' of an opening tag
    while (p < ctx->buf->last && *p != '<') {
        p++;
    }

    // add curr buf to chain out
    if (p == ctx->buf->last) {
        cl = sub_url_new_chain_buf(r, ctx);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        cl->buf = ctx->buf;

        *ctx->last_out = cl;
        cl->next = NULL;
        ctx->last_out = &cl->next;

        // simply indicate next loop of bufs
        ctx->buf = NULL;

        return NGX_OK;
    }

    ctx->state = state_lt_hit;
    ctx->pos = p + 1;

    // explicitly transfter to another state
    return sub_url_parse_state_lt_hit(r, ctx);
}


static ngx_int_t
sub_url_parse_state_lt_hit(ngx_http_request_t *r, sub_url_ctx_t *ctx)
{
    u_char *p = ctx->pos;
    size_t temp_len;
    ngx_chain_t *cl;

    // just pass by a '<'

    while (p < ctx->buf->last) {
        // not an opening tag or valid tag
        if (!isalnum(*p)) {
            ctx->state = state_normal;
            ctx->pos = p + 1;

            return sub_url_parse_state_normal(r, ctx);
        }

        // an opening tag
        do {
            p++;
        } while (p < ctx->buf->last && isalnum(*p));

        temp_len = p - ctx->pos;
        ngx_memcpy(ctx->tag.data + ctx->tag.len, ctx->pos, temp_len);
        ctx->tag.len += temp_len;

        if (p == ctx->buf->last) {
            // implicitly transfer to another state
            ctx->state = state_tag_middle;

            cl = sub_url_new_chain_buf(r, ctx);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            cl->buf = ctx->buf;

            *ctx->last_out = cl;
            cl->next = NULL;
            ctx->last_out = &cl->next;

            // and indicate next loop of bufs
            ctx->buf = NULL;

            return NGX_OK;
        }

        ctx->pos = p + 1;

        if (!isspace(*p)) {
            ctx->state = state_normal;
            return sub_url_parse_state_normal(r, ctx);
        }

        ctx->state = state_tag_captured;

        // explicitly transfer to another state
        return sub_url_parse_state_tag_captured(r, ctx);
    }

    cl = sub_url_new_chain_buf(r, ctx);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = ctx->buf;

    *ctx->last_out = cl;
    cl->next = NULL;
    ctx->last_out = &cl->next;

    // indicate next loop of bufs
    ctx->buf = NULL;

    return NGX_OK;
}


static ngx_int_t
sub_url_parse_state_tag_middle(ngx_http_request_t *r, sub_url_ctx_t *ctx)
{
    u_char *p = ctx->pos;
    size_t temp_len;
    ngx_chain_t *cl;

    // try walking through a tag
    while (p < ctx->buf->last && isalnum(*p)) {
        p++;
    }

    temp_len = p - ctx->pos;
    ngx_memcpy(ctx->tag.data + ctx->tag.len, ctx->pos, temp_len);
    ctx->tag.len += temp_len;

    // a tag is broken between bufs again
    if (p == ctx->buf->last) {
        cl = sub_url_new_chain_buf(r, ctx);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        cl->buf = ctx->buf;

        *ctx->last_out = cl;
        cl->next = NULL;
        ctx->last_out = &cl->next;

        // indicate next loop of bufs
        ctx->buf = NULL;

        return NGX_OK;
    }

    ctx->pos = p + 1;

    if (!isspace(*p)) {
        ctx->state = state_normal;
        return sub_url_parse_state_normal(r, ctx);
    }

    ctx->state = state_tag_captured;

    // explicitly transfer to another state
    return sub_url_parse_state_tag_captured(r, ctx);
}


static ngx_int_t
sub_url_parse_state_tag_captured(ngx_http_request_t *r, sub_url_ctx_t *ctx)
{
    sub_url_loc_conf_t *sulcf;
    u_char *p = ctx->pos;
    ngx_uint_t hash;
    ngx_str_t *attr;
    ngx_chain_t *cl;

    // just pass by a tag name plus one character
    //
    // another situation exists

    while (p < ctx->buf->last && isspace(*p)) {
        p++;
    }

    if (p == ctx->buf->last) {
        cl = sub_url_new_chain_buf(r, ctx);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        cl->buf = ctx->buf;

        *ctx->last_out = cl;
        cl->next = NULL;
        ctx->last_out = &cl->next;

        // indicate next loop of bufs
        ctx->buf = NULL;

        return NGX_OK;
    }

    // for the state transition below
    ctx->pos = p + 1;

    // a tag with no attributes
    // or else *p is the 1st character of an attribute now
    if (*p == '/' || *p == '>' || *p == '-') {
        ctx->state = state_normal;
        // explicitly transfer to another state
        return sub_url_parse_state_normal(r, ctx);
    }

    // *p is the 1st character of an attribute name
    ngx_memcpy(ctx->attr.data + ctx->attr.len, p, 1);
    ctx->attr.len += 1;

    hash = sub_url_hash_name(r, &ctx->tag);
    if (hash == 0) {
        return NGX_ERROR;
    }

    sulcf = ngx_http_get_module_loc_conf(r, sub_url_filter_module);
    if (sulcf == NULL) {
        return NGX_ERROR;
    }

    attr = ngx_hash_find(&sulcf->attrs_hash, hash,
                         ctx->tag.data, ctx->tag.len);
    if (attr == NULL) {
        ctx->state = state_normal;
        // explicitly transfer to another state
        return sub_url_parse_state_normal(r, ctx);
    }

    ctx->target_attr.len = attr->len;
    ngx_memcpy(ctx->target_attr.data, attr->data, attr->len);

    ctx->state = state_attr_middle;

    // explicitly transfer to another state
    return sub_url_parse_state_attr_middle(r, ctx);
}


static ngx_int_t
sub_url_parse_state_attr_middle(ngx_http_request_t *r, sub_url_ctx_t *ctx)
{
    u_char *p = ctx->pos;
    size_t temp_len;
    ngx_chain_t *cl;

    // between the 1st character (excluding) of an attribute name
    // and the last character (including) of it

    while (p < ctx->buf->last && isalnum(*p)) {
        p++;
    }

    temp_len = p - ctx->pos;
    ngx_memcpy(ctx->attr.data + ctx->attr.len, ctx->pos, temp_len);
    ctx->attr.len += temp_len;

    if (p == ctx->buf->last) {
        cl = sub_url_new_chain_buf(r, ctx);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        cl->buf = ctx->buf;

        *ctx->last_out = cl;
        cl->next = NULL;
        ctx->last_out = &cl->next;

        // indicate next loop of bufs
        ctx->buf = NULL;

        return NGX_OK;
    }

    ctx->pos = p + 1;

    // full name of an attribute is captured
    // '=' is the character with the most possibility
    // right following an attribute name
    if (*p == '=') {
        ctx->eq_hit = 1;
    } else if (*p == '/' || *p == '>') {
        ctx->state = state_normal;
        return sub_url_parse_state_normal(r, ctx);
    }

    // test an attribute name
    if (ctx->target_attr.len == ctx->attr.len
        && ngx_strncasecmp(ctx->target_attr.data, ctx->attr.data,
                           ctx->attr.len) == 0)
    {
        ctx->state = state_attr_captured;
        // explicitly transfer to another state
        return sub_url_parse_state_attr_captured(r, ctx);
    } else {
        ctx->attr.len = 0;
        ctx->state = state_attr_restart;
        return sub_url_parse_state_attr_restart(r, ctx);
    }
}


static ngx_int_t
sub_url_parse_state_attr_restart(ngx_http_request_t *r, sub_url_ctx_t *ctx)
{
    u_char *p = ctx->pos;
    ngx_chain_t *cl;

    static u_char quot = '?';

    while (p < ctx->buf->last && isspace(*p)) {
        p++;
    }

    if (p == ctx->buf->last) {
        goto new_buf;
    }

    if (*p == '>' || (quot == '?' && *p == '/')) {
        ctx->pos = p + 1;
        ctx->state = state_normal;
        return sub_url_parse_state_normal(r, ctx);
    }

    while (p < ctx->buf->last && *p != '"' && *p != '\'') {
        p++;
    }

    if (p == ctx->buf->last) {
        goto new_buf;
    }

    if (quot != '?') {
        quot = '?';

        ctx->pos = p + 1;
        ctx->state = state_tag_captured;

        return sub_url_parse_state_tag_captured(r, ctx);
    }

    quot = *p;

    do {
        p++;
    } while (p < ctx->buf->last && *p != quot);

    if (p == ctx->buf->last) {
        goto new_buf;
    }

    quot = '?';

    ctx->pos = p + 1;
    ctx->state = state_tag_captured;

    return sub_url_parse_state_tag_captured(r, ctx);

new_buf:
    cl = sub_url_new_chain_buf(r, ctx);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = ctx->buf;

    *ctx->last_out = cl;
    cl->next = NULL;
    ctx->last_out = &cl->next;

    // indicate next loop of bufs
    ctx->buf = NULL;

    return NGX_OK;
}


// valid forms:
// <link href="
// <link href ="
// <link href= "
//
// invalid forms:
// <link href />
// <link href/>
// <link href >
// <link href>
//
// if this function is called for the first time
// the 1st character is probably
// quot, = or space
// i.e. the 2nd character after the last character of an attribute name
static ngx_int_t
sub_url_parse_state_attr_captured(ngx_http_request_t *r, sub_url_ctx_t *ctx)
{
    u_char *p = ctx->pos;
    ngx_buf_t *b;
    ngx_chain_t *cl;

    // the type of quot is not determined yet
    // i.e. the opening quot is not hit yet
    if (ctx->quot == '?') {
        // = is not hit yet
        if (ctx->eq_hit == 0) {
            while (p < ctx->buf->last && isspace(*p)) {
                p++;
            }

            // add curr buf to chain out as usual
            if (p == ctx->buf->last) {
                cl = sub_url_new_chain_buf(r, ctx);
                if (cl == NULL) {
                    return NGX_ERROR;
                }

                cl->buf = ctx->buf;

                *ctx->last_out = cl;
                cl->next = NULL;
                ctx->last_out = &cl->next;

                ctx->buf = NULL;

                return NGX_OK;
            }

            ctx->pos = p + 1;

            // invalid
            if (*p != '=') {
                ctx->state = state_normal;
                return sub_url_parse_state_normal(r, ctx);
            }

            ctx->eq_hit = 1;

            return sub_url_parse_state_attr_captured(r, ctx);
        }

        // = is hit already
        while (p < ctx->buf->last && isspace(*p)) {
            p++;
        }

        // add curr buf to chain out as usual
        if (p == ctx->buf->last) {
            cl = sub_url_new_chain_buf(r, ctx);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            cl->buf = ctx->buf;

            *ctx->last_out = cl;
            cl->next = NULL;
            ctx->last_out = &cl->next;

            ctx->buf = NULL;

            return NGX_OK;
        }

        // presume standard html
        if (*p != '"' && *p != '\'') {
            ctx->state = state_normal;
            ctx->pos = p + 1;
            return sub_url_parse_state_normal(r, ctx);
        }

        ctx->quot = *p;
        ctx->pos = p + 1;

        ctx->eq_hit = 0;

        return sub_url_parse_state_attr_captured(r, ctx);
    }

    // opening quot has been hit just now
    //
    // split the original buf
    // and construct a new buf
    // not containing the opening quot
    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(b, ctx->buf, sizeof(ngx_buf_t));
    b->pos = p;

    cl->buf = b;

    // insert newly-created buf to chain in (ctx->in)
    cl->next = ctx->in ? ctx->in->next : NULL;
    ctx->in = cl;

    // mark that the current buf was processed
    ctx->buf->last = p;

    // XXX
    cl = sub_url_new_chain_buf(r, ctx);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = ctx->buf;

    *ctx->last_out = cl;
    cl->next = NULL;
    ctx->last_out = &cl->next;

    ctx->buf = NULL;

    ctx->state = state_url_start;

    return NGX_OK;
}


static ngx_int_t
sub_url_parse_state_url_start(ngx_http_request_t *r, sub_url_ctx_t *ctx)
{
    u_char *p = ctx->pos;
    ngx_buf_t *b;
    ngx_chain_t *cl;
    ngx_str_t *cdn_url;
    ngx_uint_t cdn_type;
#if 1
    sub_url_ctx_t *old_ctx;
#endif

    // look for the closing quot
    while (p < ctx->buf->last && *p != ctx->quot) {
        p++;
    }

    ctx->url.len = p - ctx->pos;
    ngx_memcpy(ctx->url.data, ctx->pos, ctx->url.len);

    // not add curr buf (containing original url) to chain out
    if (p == ctx->buf->last) {
        ctx->buf = NULL;

        ctx->state = state_url_middle;

        return NGX_OK;
    }

#if 1
    old_ctx = ctx;
#endif

    // closing quot is hit
    //
    // construct cdn url
    cdn_url = sub_url_cdn_url(r, ctx->url.data, ctx->url.len, &cdn_type);

#if 1
    // so ridiculous, causes are not caught yet
    if (ctx != old_ctx) {
        ctx = old_ctx;
    }
#endif

    if (cdn_type == CDN_TYPE_NIL) {
        ctx->state = state_normal;
        return sub_url_parse_state_normal(r, ctx);
    }
    if (cdn_url == NULL) {
        return NGX_ERROR;
    }

    // generate a new buf filled with a url only
    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->pos = ngx_pnalloc(r->pool, cdn_url->len);
    if (b->pos == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(b->pos, cdn_url->data, cdn_url->len);

    b->last = b->pos + cdn_url->len;

    b->start = b->pos;
    b->end = b->last;

    b->memory = 1;

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;

#if 1
    // so ridiculous, causes are not caught yet
    if (ctx != old_ctx) {
        ctx = old_ctx;
    }
#endif

    // add the newly generated buf to chain out
    *ctx->last_out = cl;
    cl->next = NULL;
    ctx->last_out = &cl->next;

    ctx->buf->pos = p;
    ctx->pos = p;
    ctx->state = state_normal;

    ctx->quot = '?';

    return sub_url_parse_state_normal(r, ctx);
}


static ngx_int_t
sub_url_parse_state_url_middle(ngx_http_request_t *r, sub_url_ctx_t *ctx)
{
    u_char *p = ctx->pos;
    size_t temp_len;
    ngx_buf_t *b;
    ngx_chain_t *cl;
    ngx_str_t *cdn_url;
    ngx_uint_t cdn_type;

    while (p < ctx->buf->last && *p != ctx->quot) {
        p++;
    }

    if (p == ctx->buf->last) {
        ctx->buf = NULL;

        return NGX_OK;
    }

    temp_len = p - ctx->pos;
    ngx_memcpy(ctx->url.data + ctx->url.len, ctx->pos, temp_len);
    ctx->url.len += temp_len;

    // construct cdn url
    cdn_url = sub_url_cdn_url(r, ctx->url.data, ctx->url.len, &cdn_type);

    if (cdn_type == CDN_TYPE_NIL) {
        ctx->state = state_normal;
        return sub_url_parse_state_normal(r, ctx);
    }
    if (cdn_url == NULL) {
        return NGX_ERROR;
    }

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->pos = ngx_pnalloc(r->pool, cdn_url->len);
    if (b->pos == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(b->pos, cdn_url->data, cdn_url->len);

    b->last = b->pos + cdn_url->len;

    b->start = b->pos;
    b->end = b->last;

    b->memory = 1;

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;

    // add the buf to chain out
    *ctx->last_out = cl;
    cl->next = NULL;
    ctx->last_out = &cl->next;

    ctx->buf->pos = p;
    ctx->pos = p;
    ctx->state = state_normal;

    ctx->quot = '?';

    return sub_url_parse_state_normal(r, ctx);
}


static ngx_int_t
sub_url_header_filter(ngx_http_request_t *r)
{
    sub_url_ctx_t *ctx;
    sub_url_loc_conf_t *sulcf;

    sulcf = ngx_http_get_module_loc_conf(r, sub_url_filter_module);

    if (sulcf->attrs == NULL || sulcf->attrs->nelts == 0
        || r->headers_out.content_length_n == 0
        || r->headers_out.content_type.len == 0
        || ngx_http_test_content_type(r, &sulcf->mime_types) == NULL)
    {
        return ngx_http_next_header_filter(r);
    }

    // Don't do substitution with the compressed content
    if (r->headers_out.content_encoding
        && r->headers_out.content_encoding->value.len) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http sub url filter header ignored, this may be "
                      "a compressed response.");

        return ngx_http_next_header_filter(r);
    }

    // set everything in sub_url_ctx_t to NULL or 0
    ctx = ngx_pcalloc(r->pool, sizeof(sub_url_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->buf = NULL;

    ctx->tag.data = ngx_palloc(r->pool, MAX_TAG_LEN);
    if (ctx->tag.data == NULL) {
        return NGX_ERROR;
    }

    ctx->attr.data = ngx_palloc(r->pool, MAX_ATTR_LEN);
    if (ctx->attr.data == NULL) {
        return NGX_ERROR;
    }

    ctx->target_attr.data = ngx_palloc(r->pool, MAX_ATTR_LEN);
    if (ctx->target_attr.data == NULL) {
        return NGX_ERROR;
    }

    ctx->url.data = ngx_palloc(r->pool, MAX_URL_LEN);
    if (ctx->url.data == NULL) {
        return NGX_ERROR;
    }

    ctx->quot = '?';

    ngx_http_set_ctx(r, ctx, sub_url_filter_module);

    ctx->last_out = &ctx->out;

    r->filter_need_in_memory = 1;

    if (r == r->main) {
        ngx_http_clear_content_length(r);
        ngx_http_clear_last_modified(r);
        ngx_http_clear_etag(r);
    }

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
sub_url_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t rc;
    sub_url_ctx_t *ctx;
    sub_url_loc_conf_t *sulcf;

    sulcf = ngx_http_get_module_loc_conf(r, sub_url_filter_module);

    if (sulcf->attrs == NULL || sulcf->attrs->nelts == 0) {
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, sub_url_filter_module);
    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    if (in == NULL
        && ctx->buf == NULL
        && ctx->in == NULL
        && ctx->busy == NULL)
    {
        return ngx_http_next_body_filter(r, in);
    }

    if (in) {
        if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http sub url filter \"%V\"", &r->uri);

    while (ctx->in || ctx->buf) {
        if (ctx->buf == NULL) {
            ctx->buf = ctx->in->buf;
            ctx->in = ctx->in->next;

#if 0
            if (ngx_buf_size(ctx->buf) == 0) {
                continue;
            }
#endif

            ctx->pos = ctx->buf->pos;
        }

        switch (ctx->state) {
        case state_normal:
            rc = sub_url_parse_state_normal(r, ctx);
            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            break;

        case state_lt_hit:
            rc = sub_url_parse_state_lt_hit(r, ctx);
            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            break;

        case state_tag_middle:
            rc = sub_url_parse_state_tag_middle(r, ctx);
            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            break;

        case state_tag_captured:
            rc = sub_url_parse_state_tag_captured(r, ctx);
            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            break;

        case state_attr_middle:
            rc = sub_url_parse_state_attr_middle(r, ctx);
            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            break;

        case state_attr_restart:
            rc = sub_url_parse_state_attr_restart(r, ctx);
            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            break;

        case state_attr_captured:
            rc = sub_url_parse_state_attr_captured(r, ctx);
            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            break;

        case state_url_start:
            rc = sub_url_parse_state_url_start(r, ctx);
            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            break;

        case state_url_middle:
            rc = sub_url_parse_state_url_middle(r, ctx);
            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            break;

        default:
            return NGX_ERROR;
        }
    }

    // output nothing
    if (ctx->out == NULL && ctx->busy == NULL) {
        return NGX_OK;
    }

    return sub_url_output(r, ctx);
}


static ngx_int_t
sub_url_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = sub_url_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = sub_url_body_filter;

    return NGX_OK;
}


static void *
sub_url_create_loc_conf(ngx_conf_t *cf)
{
    sub_url_loc_conf_t *sulcf;

    // set everything in sub_url_loc_conf_t to NULL or 0
    sulcf = ngx_pcalloc(cf->pool, sizeof(sub_url_loc_conf_t));
    if (sulcf == NULL) {
        return NULL;
    }

    return sulcf;
}


static char *
sub_url_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    sub_url_loc_conf_t *prev = parent;
    sub_url_loc_conf_t *conf = child;

    size_t i;

    ngx_hash_key_t *attr;
    ngx_hash_init_t attrs_hash;

    if (prev->attrs && prev->attrs_hash.buckets == NULL) {
        attrs_hash.hash = &prev->attrs_hash;
        attrs_hash.key = ngx_hash_key_lc;
        attrs_hash.max_size = 1024;
        attrs_hash.bucket_size = ngx_cacheline_size;
        attrs_hash.name = "attrs_hash";
        attrs_hash.pool = cf->pool;
        attrs_hash.temp_pool = NULL;

        if (ngx_hash_init(&attrs_hash, prev->attrs->elts, prev->attrs->nelts)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    if (conf->attrs == NULL) {
        conf->attrs = prev->attrs;
        conf->attrs_hash = prev->attrs_hash;
    }

    if (conf->attrs == NULL) {
        return NGX_CONF_OK;
    }

    if (conf->attrs == NULL) {
        conf->attrs = ngx_array_create(cf->pool, 2, sizeof(ngx_hash_key_t));
        if (conf->attrs == NULL) {
            return NGX_CONF_ERROR;
        }

        for (i = 0; sub_url_default_attrs[i].key.len; i++) {
            attr = ngx_array_push(conf->attrs);
            if (attr == NULL) {
                return NGX_CONF_ERROR;
            }

            attr->key = sub_url_default_attrs[i].key;
            attr->key_hash = ngx_hash_key_lc(sub_url_default_attrs[i].key.data,
                                             sub_url_default_attrs[i].key.len);
            attr->value = sub_url_default_attrs[i].value;
        }
    }

    if (conf->attrs_hash.buckets == NULL) {
        attrs_hash.hash = &conf->attrs_hash;
        attrs_hash.key = ngx_hash_key_lc;
        attrs_hash.max_size = 1024;
        attrs_hash.bucket_size = ngx_cacheline_size;
        attrs_hash.name = "attrs_hash";
        attrs_hash.pool = cf->pool;
        attrs_hash.temp_pool = NULL;

        if (ngx_hash_init(&attrs_hash, conf->attrs->elts, conf->attrs->nelts)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    ngx_conf_merge_str_value(conf->cdn_url_prefix_pic,
                             prev->cdn_url_prefix_pic, "");
    ngx_conf_merge_str_value(conf->cdn_url_prefix_css,
                             prev->cdn_url_prefix_css, "");
    ngx_conf_merge_str_value(conf->cdn_url_prefix_js,
                             prev->cdn_url_prefix_js, "");

    if (conf->reserved_domains == NULL) {
        conf->reserved_domains = prev->reserved_domains;
    }

#if 0
    if (ngx_http_merge_types(cf, &conf->mime_types_keys, &conf->mime_types,
                             &prev->mime_types_keys, &prev->mime_types,
                             ngx_http_html_default_types)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_merge_types(cf, &conf->file_exts_keys, &conf->file_exts,
                             &prev->file_exts_keys, &prev->file_exts,
                             sub_url_default_file_exts)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
#endif

    return NGX_CONF_OK;
}
