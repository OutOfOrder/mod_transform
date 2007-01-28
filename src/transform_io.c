/**
 *    Copyright (c) 2002 WebThing Ltd
 *    Copyright (c) 2004 Edward Rudd
 *    Copyright (c) 2004 Paul Querna
 *    Authors:    Nick Kew <nick webthing.com>
 *                Edward Rudd <urkle at outoforder dot com>
 *                Paul Querna <chip at outoforder dot com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */



#include "mod_transform.h"
#define HAVE_MOD_DEPENDS 0
#if HAVE_MOD_DEPENDS
#include "mod_depends.h"
#endif
#include "mod_transform_private.h"

static apr_status_t io_pass_failure(ap_filter_t * filter, const char *msg,
                                 transform_notes * notes)
{
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, filter->r, "Transform IO: %s",
                  msg);
    return HTTP_INTERNAL_SERVER_ERROR;
}


int transform_xmlio_output_write(void *context, const char *buffer,
                                        int len)
{
    if (len > 0) {
        transform_xmlio_output_ctx *octx =
            (transform_xmlio_output_ctx *) context;
        ap_fwrite(octx->next, octx->bb, buffer, len);
    }
    return len;
}

int transform_xmlio_output_close(void *context)
{
    transform_xmlio_output_ctx *octx = (transform_xmlio_output_ctx *) context;
    apr_bucket *b = apr_bucket_eos_create(octx->bb->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(octx->bb, b);
    return 0;
}

/**
 * This Function is part of a patch to APR-Util: 
 *   http://issues.apache.org/bugzilla/show_bug.cgi?id=28453
 * Thanks to Nick Kew :)
 */
/* Resolve relative to a base.  This means host/etc, and (crucially) path */
static apr_status_t ex_apr_uri_resolve_relative(apr_pool_t * pool,
                                                apr_uri_t * base,
                                                apr_uri_t * uptr)
{
    if (uptr == NULL
        || base == NULL || !base->is_initialized || !uptr->is_initialized) {
        return APR_EGENERAL;
    }
    /* The interesting bit is the path.  */
    if (uptr->path == NULL) {
        if (uptr->hostname == NULL) {
            /* is this compatible with is_initialised?  Harmless in any case */
            uptr->path = base->path ? base->path : apr_pstrdup(pool, "/");
        }
        else {
            /* deal with the idiosyncracy of APR allowing path==NULL
             ** without risk of breaking back-compatibility
             */
            uptr->path = apr_pstrdup(pool, "/");
        }
    }
    else if (uptr->path[0] != '/') {
        size_t baselen;
        const char *basepath = base->path ? base->path : "/";
        const char *path = uptr->path;
        const char *base_end = ap_strrchr_c(basepath, '/');

        /* if base is nonsensical, bail out */
        if (basepath[0] != '/') {
            return APR_EGENERAL;
        }
        /* munch "up" components at the start, and chop them from base path */
        while (!strncmp(path, "../", 3)) {
            while (base_end > basepath) {
                if (*--base_end == '/') {
                    break;
                }
            }
            path += 3;
        }
        /* munch "here" components at the start */
        while (!strncmp(path, "./", 2)) {
            path += 2;
        }
        baselen = base_end - basepath + 1;
        uptr->path = apr_palloc(pool, baselen + strlen(path) + 1);
        memcpy(uptr->path, basepath, baselen);
        strcpy(uptr->path + baselen, path);
    }

    /* The trivial bits are everything-but-path */
    if (uptr->scheme == NULL) {
        uptr->scheme = base->scheme;
    }
    if (uptr->hostinfo == NULL) {
        uptr->hostinfo = base->hostinfo;
    }
    if (uptr->user == NULL) {
        uptr->user = base->user;
    }
    if (uptr->password == NULL) {
        uptr->password = base->password;
    }
    if (uptr->hostname == NULL) {
        uptr->hostname = base->hostname;
    }
    if (uptr->port_str == NULL) {
        uptr->port_str = base->port_str;
    }
    if (uptr->hostent == NULL) {
        uptr->hostent = base->hostent;
    }
    if (!uptr->port) {
        uptr->port = base->port;
    }
    return APR_SUCCESS;
}

static const char *find_relative_uri(ap_filter_t * f, const char *orig_href)
{
    apr_uri_t url;
    apr_uri_t base_url;
    const char *basedir;
    char *href;
    if (orig_href) {
        if (apr_uri_parse(f->r->pool, orig_href, &url) == APR_SUCCESS) {
            basedir = ap_make_dirstr_parent(f->r->pool, f->r->filename);
            apr_uri_parse(f->r->pool,
                          apr_psprintf(f->r->pool, "file://%s", basedir),
                          &base_url);
            ex_apr_uri_resolve_relative(f->r->pool, &base_url, &url);
            href = apr_uri_unparse(f->r->pool, &url, 0);
#if HAVE_MOD_DEPENDS
            depends_add_file(f->r, url.path);
#endif
            return href;
        }
    }
    return orig_href;
}

apr_status_t transform_apachefs_filter(ap_filter_t * f, apr_bucket_brigade * bb)
{
    apr_status_t rv;
    transform_xmlio_input_ctx *ctxt = f->ctx;
    apr_bucket_brigade *data = ctxt->bb;
    rv = ap_save_brigade(f, &data, &bb, f->r->pool);
    ctxt->bb = data;
    return rv;
}


static int transform_xmlio_input_read(void *context, char *buffer, int len)
{
    apr_status_t rv;
    apr_size_t slen;
    apr_bucket *e;
    apr_bucket_brigade *newbb;
    transform_xmlio_input_ctx *input_ctx = context;
    slen = len;

    if(!(input_ctx->bb)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, input_ctx->f->r,
                      "mod_transform: Input Brigade was NULL.");
        len = 0;
        return -1;
    }

    rv = apr_brigade_flatten(input_ctx->bb, buffer, &slen);

    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, input_ctx->f->r,
                      "mod_transform: Unable to Flatten Brigade into xmlIO Buffer");
        return -1;
    }

    rv = apr_brigade_partition(input_ctx->bb, slen, &e);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, input_ctx->f->r,
                      "mod_transform: Brigade Partition Failed!");
        return -1;
    }

    newbb = apr_brigade_split(input_ctx->bb, e);

    rv = apr_brigade_destroy(input_ctx->bb);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, input_ctx->f->r,
                      "mod_transform: Brigade Destroy Failed!");
        return -1;
    }

    input_ctx->bb = newbb;
    return slen;
}

static int transform_xmlio_input_close(void *context)
{
    transform_xmlio_input_ctx *input_ctx = context;
    ap_destroy_sub_req(input_ctx->rr);
    apr_pool_destroy(input_ctx->p);
    return 0;
}

static xmlParserInputBufferPtr 
    transform_input_from_subrequest(ap_filter_t *f, const char *URI, xmlCharEncoding enc)
{
    int rr_status;
    xmlParserInputBufferPtr ret;
    transform_xmlio_input_ctx *input_ctx;
    /* TODO: This pool should be re-used for each file... */
    apr_pool_t* subpool;

    apr_pool_create(&subpool, f->r->pool);

    input_ctx = apr_palloc(subpool, sizeof(input_ctx));
    input_ctx->p = subpool;
    input_ctx->bb = NULL;
    input_ctx->f = f;

    input_ctx->rr = ap_sub_req_lookup_uri(URI, f->r, NULL);

    if (input_ctx->rr->status != HTTP_OK) {
        ap_destroy_sub_req(input_ctx->rr);
        apr_pool_destroy(subpool);
        return __xmlParserInputBufferCreateFilename(find_relative_uri(f, URI),
                                                    enc);
    }

    ap_add_output_filter(APACHEFS_FILTER_NAME,  input_ctx, input_ctx->rr, f->r->connection);

#if HAVE_MOD_DEPENDS
    depends_add_file(f->r, input_ctx->rr->filename);
#endif
    rr_status = ap_run_sub_req(input_ctx->rr);

    if(rr_status != OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, input_ctx->f->r,
                      "mod_transform: Subrequest for '%s' failed with '%d'", URI, rr_status);
        ap_destroy_sub_req(input_ctx->rr);
        apr_pool_destroy(subpool);
        return __xmlParserInputBufferCreateFilename(find_relative_uri(f, URI),
                                                    enc);
    }

    ret = xmlAllocParserInputBuffer(enc);

    if (ret != NULL) {
        ret->context = input_ctx;
        ret->readcallback = transform_xmlio_input_read;
        ret->closecallback = transform_xmlio_input_close;
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, input_ctx->f->r,
                      "mod_transform: Failed to create ParserInputBuffer");
        ap_destroy_sub_req(input_ctx->rr);
        apr_pool_destroy(subpool);
        return __xmlParserInputBufferCreateFilename(find_relative_uri(f, URI), enc);
    }

    return ret;
}

xmlParserInputBufferPtr transform_get_input(const char *URI,
                                                   xmlCharEncoding enc)
{
    ap_filter_t *f = (ap_filter_t *) xmlGenericErrorContext;
    dir_cfg *dconf;

    /* Uhm. Our Context got killed somehow. bad. */
    if(f == NULL)
        return NULL;

    dconf = ap_get_module_config(f->r->per_dir_config,
                                          &transform_module);

    if (URI == NULL)
        return NULL;

    if (dconf->opts & USE_APACHE_FS) {
        /* We want to use an Apache based Filesystem for Libxml. Let the fun begin. */
        if(strncmp(URI,"file:///etc/xml/catalog", sizeof("file:///etc/xml/catalog")) == 0){
#if HAVE_MOD_DEPENDS
            depends_add_file(f->r, "/etc/xml/catalog");
#endif
            return __xmlParserInputBufferCreateFilename(URI, enc);
        }
        else {
            return transform_input_from_subrequest(f, URI, enc);
        }
    }
    else {
        /* TODO: Fixup Relative Paths here */
        return __xmlParserInputBufferCreateFilename(find_relative_uri(f, URI),
                                                    enc);
    }
}

