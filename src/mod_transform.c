/**
 *    Copyright (c) 2002, WebThing Ltd
 *    Author:    Nick Kew <nick@webthing.com>
 *
 *  Current state: pre-release; some parts work, but none of it
 *  is suitable for an operational server.  Subject to much change
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


#define XSLT_FILTER_NAME "XSLT"

#include "mod_transform.h"

#include "apr_buckets.h"
#include "apr_strings.h"

module AP_MODULE_DECLARE_DATA transform_module;

/* BEGIN svr cfg / stylesheet cache section */
typedef struct cached_xslt
{
    const char *id;
    xsltStylesheetPtr transform;
    struct cached_xslt *next;
} cached_xslt;

typedef struct svr_cfg
{
    cached_xslt *data;
} svr_cfg;

static void *get_cached_xslt(svr_cfg * sconf, const char *descriptor)
{
    cached_xslt *p;
    if (!descriptor)
        return 0;

    for (p = sconf->data; p; p = p->next)
        if (!strcmp(descriptor, p->id))
            return p->transform;

    return 0;
}

static const char *transform_cache_xslt(cmd_parms * cmd, void *cfg,
                                    const char *url, const char *path)
{
    svr_cfg *conf =
        ap_get_module_config(cmd->server->module_config,
                             &transform_module);
    xsltStylesheetPtr xslt = xsltParseStylesheetFile(path);
    if (url && path && xslt) {
        cached_xslt *me = apr_palloc(cmd->pool, sizeof(cached_xslt));
//      cached_xslt* prev = conf->data ;
        me->id = apr_pstrdup(cmd->pool, url);
        me->transform = xslt;
        me->next = conf->data;
        conf->data = me;
        //apr_hash_set(conf->hash, url, APR_HASH_KEY_STRING, xslt) ;
        ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, cmd->pool,
                      "Cached precompiled XSLT %s", url);
        return NULL;
    }
    else {
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, cmd->pool,
                      "Error fetching or compiling XSLT from %s", path);
        return "Error trying to precompile XSLT";
    }
}
static apr_status_t freeCache(void *conf)
{
    cached_xslt *p;
    svr_cfg *cfg = conf;
    for (p = cfg->data; p; p = p->next)
        xsltFreeStylesheet(p->transform);
    return APR_SUCCESS;
}
static void *create_server_cfg(apr_pool_t * p, server_rec * x)
{
    svr_cfg *cfg = apr_pcalloc(p, sizeof(svr_cfg));
    apr_pool_cleanup_register(p, cfg, freeCache, apr_pool_cleanup_null);
    return cfg;
}

/* END svr cfg / stylesheet cache section */

typedef struct dir_cfg
{
    const char *xslt;
} dir_cfg;

typedef struct
{
    const char *xslt;
    xmlDocPtr document;
} modxml_notes;

#define FAIL 500

static apr_status_t pass_failure(ap_filter_t * filter, const char *msg,
                                 modxml_notes * notes)
{
#if 0
    modxml_ctx *ctx = (modxml_ctx *) filter->ctx;
    if (ctx->buf) {
        ap_fwrite(filter->next, ctx->bb, ctx->buf, ctx->sz);
    }
    else {
        char buf[4096];
        ssize_t bytes;
        while (bytes = read(ctx->fd, buf, 4096), bytes > 0)
            ap_fwrite(filter->next, ctx->bb, buf, bytes);
    }
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, filter->r, msg);
    notes->ctype = "text/xml";
#else
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, filter->r, msg);
#endif
    return FAIL;
}


typedef struct
{
    ap_filter_t *next;
    apr_bucket_brigade *bb;
} transform_output_ctx;

static int writeCallback(void *context, const char *buffer, int len)
{
    if (len > 0) {
        transform_output_ctx *octx = (transform_output_ctx *) context;
        ap_fwrite(octx->next, octx->bb, buffer, len);
    }
    return len;
}
static int closeCallback(void *context)
{
    transform_output_ctx *octx = (transform_output_ctx *) context;
    apr_bucket *b = apr_bucket_eos_create(octx->bb->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(octx->bb, b);
    return 0;
}

static apr_status_t transform_run(ap_filter_t * f, xmlDocPtr doc)
{
    size_t length;
    transform_output_ctx output_ctx;
    int stylesheet_is_cached = 0;
    xsltStylesheetPtr transform = NULL;
    xmlDocPtr result = NULL;
    xmlOutputBufferPtr output;

    modxml_notes *notes =
        ap_get_module_config(f->r->request_config, &transform_module);
    svr_cfg *sconf = ap_get_module_config(f->r->server->module_config,
                                          &transform_module);

    if (!doc)
        return pass_failure(f, "XSLT: Couldn't parse document", notes);

    if (notes->xslt)
        if (transform = get_cached_xslt(sconf, notes->xslt), transform)
            stylesheet_is_cached = 1;
        else
            transform = xsltParseStylesheetFile(notes->xslt);
    else
        transform = xsltLoadStylesheetPI(doc);

    if (!transform) {
        return pass_failure(f, "XSLT: Couldn't load transform", notes);
    }
    result = xsltApplyStylesheet(transform, doc, 0);
    if (!result) {
        if (!stylesheet_is_cached)
            xsltFreeStylesheet(transform);
        return pass_failure(f, "XSLT: Couldn't run transform", notes);
    }
    if (transform->mediaType) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r, 
            "Setting content-type to: %s", transform->mediaType);
        ap_set_content_type(f->r, apr_pstrdup(f->r->pool,transform->mediaType));
    }
    output_ctx.next = f->next;
    output_ctx.bb = apr_brigade_create(f->r->pool,
                                       apr_bucket_alloc_create(f->r->pool));
    output = xmlOutputBufferCreateIO(&writeCallback, &closeCallback,
                                     &output_ctx, 0);
    length = xsltSaveResultTo(output, result, transform);
    if (!f->r->chunked)
        ap_set_content_length(f->r, length);

    xmlOutputBufferClose(output);
    xmlFreeDoc(result);
    if (!stylesheet_is_cached)
        xsltFreeStylesheet(transform);

    ap_pass_brigade(output_ctx.next, output_ctx.bb);
    return APR_SUCCESS;
}

static apr_status_t transform_filter(ap_filter_t * f,
                                      apr_bucket_brigade * bb)
{
    apr_bucket *b;
    const char *buf = 0;
    apr_size_t bytes = 0;
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) f->ctx;  // will be 0 first time
    apr_status_t ret = APR_SUCCESS;

    /* Check request notes to see any altered configuration */
    if (!ctxt) {
        const char *note;
    /*    if (!f->r->content_type || (strncmp(f->r->content_type, "text/xml", 8) &&
                strncmp(f->r->content_type, "application/xml", 15) &&
                strncmp(f->r->content_type, "application/xhtml", 17) &&
                                strncmp(f->r->content_type, "text/html", 9))) {
            ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, f->r,
                        "Filter removed due to write content type: %s", f->r->content_type);
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }*/
        note = apr_table_get(f->r->notes, "TRANSFORM_MODE");
        if (note) {
            if (!apr_strnatcasecmp(note, "off")) {
                ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, f->r,
                            "Filter removed due to note");
                ap_remove_output_filter(f);
                return ap_pass_brigade(f->next, bb);
            }
        }
    }

    if ((f->r->proto_num >= 1001) && !f->r->main && !f->r->prev)
        f->r->chunked = 1;

    for (b = APR_BRIGADE_FIRST(bb);
         b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b)) {
        if (APR_BUCKET_IS_EOS(b)) {
            if (ctxt) {         /* got input the normal way */
                xmlParseChunk(ctxt, buf, 0, 1);
                ret = transform_run(f, ctxt->myDoc);
                xmlFreeParserCtxt(ctxt);
            }
            else {              /* someone passed us an in-memory doctree */
                modxml_notes *notes =
                    ap_get_module_config(f->r->request_config,
                                         &transform_module);
                ret = transform_run(f, notes->document);
                if (notes->document)
                    xmlFreeDoc(notes->document);
            }
        }
        else if (apr_bucket_read(b, &buf, &bytes, APR_BLOCK_READ)
                 == APR_SUCCESS) {
            if (ctxt)
                xmlParseChunk(ctxt, buf, bytes, 0);
            else if (bytes >= 4)
                f->ctx = ctxt = xmlCreatePushParserCtxt(0, 0, buf, bytes, 0);
        }
    }
    apr_brigade_destroy(bb);
    return ret;
}

/* -------------------------------------------------------------
    Config command stuff
   -------------------------------------------------------------
*/

static void *xml_merge_dir_config(apr_pool_t * p, void *basev, void *addv)
{
    dir_cfg *from = basev;
    dir_cfg *merge = addv;
    dir_cfg *to = apr_palloc(p, sizeof(dir_cfg));

    to->xslt = (merge->xslt != 0) ? merge->xslt : from->xslt;

    return to;
}

static void *xml_create_dir_config(apr_pool_t * p, char *x)
{
    dir_cfg *conf = apr_pcalloc(p, sizeof(dir_cfg));
    return conf;
}
static const char *use_xslt(cmd_parms * cmd, void *cfg, const char *xslt)
{
    dir_cfg *conf = (dir_cfg *) cfg;
    conf->xslt = apr_pstrdup(cmd->pool, xslt);
    return NULL;
}

/* basic command set; no content negotiation yet */

static int init_notes(request_rec * r)
{
    dir_cfg *conf = ap_get_module_config(r->per_dir_config,
                                         &transform_module);
    modxml_notes *notes = apr_pcalloc(r->pool, sizeof(modxml_notes));
    notes->xslt = conf->xslt;
    
    ap_set_module_config(r->request_config, &transform_module, notes);
    return OK;
}

static const command_rec transform_cmds[] = {

    AP_INIT_TAKE1("TransformSet", use_xslt, NULL, OR_ALL,
                  "Stylesheet to use"),

    AP_INIT_TAKE2("TransformCache", transform_cache_xslt, NULL, RSRC_CONF,
                  "URL and Path for stylesheet to preload"),
    {NULL}
};

static void transform_hooks(apr_pool_t * p)
{
    ap_hook_post_read_request(init_notes, NULL, NULL, APR_HOOK_MIDDLE);

    ap_register_output_filter(XSLT_FILTER_NAME, transform_filter, NULL,
                              AP_FTYPE_RESOURCE);

};

module AP_MODULE_DECLARE_DATA transform_module = {
    STANDARD20_MODULE_STUFF,
    xml_create_dir_config,
    xml_merge_dir_config,
    create_server_cfg,
    NULL,
    transform_cmds,
    transform_hooks
};

/* Exported Functions */
void mod_transform_set_XSLT(request_rec * r, const char *name)
{
    modxml_notes *notes = ap_get_module_config(r->request_config,
                                               &transform_module);
    notes->xslt = apr_pstrdup(r->pool, name);
}

void mod_transform_XSLTDoc(request_rec * r, xmlDocPtr doc)
{
    modxml_notes *notes = ap_get_module_config(r->request_config,
                                               &transform_module);
    notes->document = doc;
}
