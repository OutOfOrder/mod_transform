/**
 *    Copyright (c) 2002 WebThing Ltd
 *    Copyright (c) 2004 Edward Rudd
 *    Copyright (c) 2004 Paul Querna
 *    Authors:    Nick Kew <nick webthing.com>
 *                Edward Rudd <urkle at outoforder dot com>
 *                Paul Querna <chip at force-elite.com>
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

#include "mod_transform_private.h"

static void transform_error_cb(void *ctx, const char *msg, ...)
{
    va_list args;
    char *fmsg;
    ap_filter_t *f = (ap_filter_t *) ctx;
    va_start(args, msg);
    fmsg = apr_pvsprintf(f->r->pool, msg, args);
    va_end(args);
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r,
                  "mod_transform::libxml2_error: %s", fmsg);
}

static apr_status_t pass_failure(ap_filter_t * filter, const char *msg,
                                 transform_notes * notes)
{
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, filter->r, "mod_transform: %s",
                  msg);
    return HTTP_INTERNAL_SERVER_ERROR;
}


/* Search a docPtr for a xml-stylesheet PI. Return this Node. Null Otherwise. */
static xmlNodePtr find_stylesheet_node(xmlDocPtr doc)
{
    xmlNodePtr child;
    child = doc->children;
    while ((child != NULL) && (child->type != XML_ELEMENT_NODE)) {
        if ((child->type == XML_PI_NODE) && 
            (xmlStrEqual(child->name, BAD_CAST "xml-stylesheet"))) {
            if (child->content != NULL) {
                return child;
            }
        }
        child = child->next;
    }
    return NULL;
}

static apr_status_t transform_run(ap_filter_t * f, xmlDocPtr doc)
{
    size_t length;
    transform_xmlio_output_ctx output_ctx;
    int stylesheet_is_cached = 0;
    xsltStylesheetPtr transform = NULL;
    xmlDocPtr result = NULL;
    xmlNodePtr pi_node;
    xmlOutputBufferPtr output;
    xmlParserInputBufferCreateFilenameFunc orig;
    transform_notes *notes =
        ap_get_module_config(f->r->request_config, &transform_module);
    dir_cfg *dconf = ap_get_module_config(f->r->per_dir_config,
                                          &transform_module);
    svr_cfg *sconf = ap_get_module_config(f->r->server->module_config,
                                          &transform_module);

    if (!doc) {
        return pass_failure(f, "XSLT: Couldn't parse XML Document", notes);
    }

    orig = xmlParserInputBufferCreateFilenameDefault(transform_get_input);


    if (dconf->opts & XINCLUDES) {
        xmlXIncludeProcessFlags(doc,
                                XML_PARSE_RECOVER | XML_PARSE_XINCLUDE |
                                XML_PARSE_NONET);
    }

    if (ap_is_initial_req(f->r) && notes->xslt) {
        if (transform = transform_cache_get(sconf, notes->xslt), transform) {
            stylesheet_is_cached = 1;
        }
        else {
            transform = xsltParseStylesheetFile(notes->xslt);
        }
    }
    else if(dconf->xslt != NULL) {
        if(transform = transform_cache_get(sconf, dconf->xslt), transform) {
            stylesheet_is_cached = 1;
        }
        else {
            transform = xsltParseStylesheetFile(dconf->xslt);
        }
    }
    else {
        pi_node = find_stylesheet_node(doc);
        if(pi_node == NULL && dconf->default_xslt != NULL){
            transform = xsltParseStylesheetFile(dconf->default_xslt);
        }
        else if(pi_node == NULL) {
            /* no node was found, plus no default. */
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r, 
                          "mod_transform: XSL not named in XML and No Default XSLT set");
            transform = NULL;
        }
        else {
            transform = xsltLoadStylesheetPI(doc);        
        }
    }

    if (!transform) {
        /* TODO: Need better error reporting here. Why couldn't we Load it? */
        xmlParserInputBufferCreateFilenameDefault(orig);
        return pass_failure(f, "XSLT: Couldn't load transform", notes);
    }
    result = xsltApplyStylesheet(transform, doc, 0);
    if (!result) {
        if (!stylesheet_is_cached) {
            xsltFreeStylesheet(transform);
        }
        /* TODO: Need better error reporting here. What Went Wrong? */
        xmlParserInputBufferCreateFilenameDefault(orig);
        return pass_failure(f, "XSLT: Couldn't run transform", notes);
    }

    if (transform->mediaType) {
        /* Note: If the XSLT We are using doesn't have an encoding, 
           We will use the server default. */
        if (transform->encoding) {
            /* 
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r,
                          "Setting content-type to: '%s; charset=%s'",
                          transform->mediaType, transform->encoding);
            */
            ap_set_content_type(f->r,
                                apr_psprintf(f->r->pool, "%s; charset=%s",
                                             transform->mediaType,
                                             transform->encoding));
        }
        else if (doc->encoding) {
            /*
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r,
                          "Setting content-type to: '%s; charset=%s'",
                          transform->mediaType, doc->encoding);
            */
            ap_set_content_type(f->r,
                                apr_psprintf(f->r->pool, "%s; charset=%s",
                                             transform->mediaType,
                                             doc->encoding));
        }
        else {
            /*
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r,
                          "Setting content-type to: '%s'",
                          transform->mediaType);
            */
            ap_set_content_type(f->r,
                                apr_pstrdup(f->r->pool,
                                            transform->mediaType));
        }
    }
    else if (transform->method) {
        if (!strcmp(transform->method, "html")) {
            /*
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r,
                          "Setting content-type as default to: text/html");
            */
            ap_set_content_type(f->r, apr_pstrdup(f->r->pool, "text/html"));
        }
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, f->r,
                      "mod_transform: Warning, no content type was set! Fix your XSLT!");
    }

    output_ctx.next = f->next;
    output_ctx.bb = apr_brigade_create(f->r->pool,
                                       apr_bucket_alloc_create(f->r->pool));
    output =
        xmlOutputBufferCreateIO(&transform_xmlio_output_write,
                                &transform_xmlio_output_close, &output_ctx,
                                0);
    length = xsltSaveResultTo(output, result, transform);
    if (!f->r->chunked)
        ap_set_content_length(f->r, length);

    xmlOutputBufferClose(output);
    xmlFreeDoc(result);
    if (!stylesheet_is_cached)
        xsltFreeStylesheet(transform);

    xmlParserInputBufferCreateFilenameDefault(orig);

    ap_pass_brigade(output_ctx.next, output_ctx.bb);
    return APR_SUCCESS;
}

static apr_status_t transform_filter(ap_filter_t * f, apr_bucket_brigade * bb)
{
    apr_bucket *b;
    const char *buf = 0;
    apr_size_t bytes = 0;
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) f->ctx;
    apr_status_t ret = APR_SUCCESS;
    void *orig_error_cb = xmlGenericErrorContext;
    xmlGenericErrorFunc orig_error_func = xmlGenericError;

    xmlSetGenericErrorFunc((void *) f, transform_error_cb);

#if 0
    /* For now, we do not handle subrequests, because libxml2 really makes it hard... */
    if(!ap_is_initial_req(f->r)) {
        ap_remove_output_filter(f);
        return ap_pass_brigade(f->next, bb);
    }
#endif

    /* First Run of this Filter */
    if (!ctxt) {
        /* unset content-length */
        apr_table_unset(f->r->headers_out, "Content-Length");

        /* TODO: Find a better way to determine if any resources needed to 
           create this document have changed.
           TODO: We can now hook the ApacheFS to get the file mtimes.....
           apr_table_unset(f->r->headers_out, "Last-Modified"); 
         */
    }

    if ((f->r->proto_num >= 1001) && !f->r->main && !f->r->prev)
        f->r->chunked = 1;

    for (b = APR_BRIGADE_FIRST(bb);
         b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b)) {
        if (APR_BUCKET_IS_EOS(b)) {
            if (ctxt) {         /* done reading the file. run the transform now */
                xmlParseChunk(ctxt, buf, 0, 1);
                ret = transform_run(f, ctxt->myDoc);
                xmlFreeParserCtxt(ctxt);
            }
        }
        else if (apr_bucket_read(b, &buf, &bytes, APR_BLOCK_READ)
                 == APR_SUCCESS) {
            if (ctxt) {
                xmlParseChunk(ctxt, buf, bytes, 0);
            }
            else {
                f->ctx = ctxt = xmlCreatePushParserCtxt(0, 0, buf, bytes, 0);
#if LIBXML_VERSION >= 20600
                xmlCtxtUseOptions(ctxt, XML_PARSE_NOENT | XML_PARSE_NOCDATA);
#endif
                ctxt->directory = xmlParserGetDirectory(f->r->filename);
            }
        }
    }
    apr_brigade_destroy(bb);

    xmlSetGenericErrorFunc(orig_error_cb,  orig_error_func);

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

    /* This code comes from mod_autoindex's IndexOptions */
    if (merge->opts & NO_OPTIONS) {
        /*
         * If the current directory says 'no options' then we also
         * clear any incremental mods from being inheritable further down.
         */
        to->opts = NO_OPTIONS;
        to->incremented_opts = 0;
        to->decremented_opts = 0;
    }
    else {
        /*
         * If there were any nonincremental options selected for
         * this directory, they dominate and we don't inherit *anything.*
         * Contrariwise, we *do* inherit if the only settings here are
         * incremental ones.
         */
        if (merge->opts == 0) {
            to->incremented_opts = (from->incremented_opts
                                    | merge->incremented_opts)
                & ~merge->decremented_opts;
            to->decremented_opts = (from->decremented_opts
                                    | merge->decremented_opts);
            /*
             * We may have incremental settings, so make sure we don't
             * inadvertently inherit an IndexOptions None from above.
             */
            to->opts = (from->opts & ~NO_OPTIONS);
        }
        else {
            /*
             * There are local nonincremental settings, which clear
             * all inheritance from above.  They *are* the new base settings.
             */
            to->opts = merge->opts;;
        }
        /*
         * We're guaranteed that there'll be no overlap between
         * the add-options and the remove-options.
         */
        to->opts |= to->incremented_opts;
        to->opts &= ~to->decremented_opts;
    }

    return to;
}

static void *create_server_cfg(apr_pool_t * p, server_rec * x)
{
    svr_cfg *cfg = apr_pcalloc(p, sizeof(svr_cfg));
    apr_pool_cleanup_register(p, cfg, transform_cache_free, apr_pool_cleanup_null);
    cfg->announce = 1;
    return cfg;
}

static void *xml_create_dir_config(apr_pool_t * p, char *x)
{
    dir_cfg *conf = apr_pcalloc(p, sizeof(dir_cfg));
    /* Enable XIncludes By Default (backwards compat..?) */
    conf->opts = 0 & XINCLUDES;
    conf->incremented_opts = 0;
    conf->decremented_opts = 0;
    conf->xslt = NULL;
    return conf;
}

static const char *use_xslt(cmd_parms * cmd, void *cfg, const char *xslt)
{
    dir_cfg *conf = (dir_cfg *) cfg;
    conf->xslt = apr_pstrdup(cmd->pool, xslt);
    return NULL;
}

static int init_notes(request_rec * r)
{
    dir_cfg *conf = ap_get_module_config(r->per_dir_config,
                                         &transform_module);
    transform_notes *notes = apr_pcalloc(r->pool, sizeof(transform_notes));
    notes->xslt = conf->xslt;

    ap_set_module_config(r->request_config, &transform_module, notes);
    return OK;
}

static const char *add_opts(cmd_parms * cmd, void *d, const char *optstr)
{
    char *w;
    apr_int32_t opts;
    apr_int32_t opts_add;
    apr_int32_t opts_remove;
    char action;
    dir_cfg *d_cfg = (dir_cfg *) d;

    opts = d_cfg->opts;
    opts_add = d_cfg->incremented_opts;
    opts_remove = d_cfg->decremented_opts;
    while (optstr[0]) {
        int option = 0;

        w = ap_getword_conf(cmd->pool, &optstr);

        if ((*w == '+') || (*w == '-')) {
            action = *(w++);
        }
        else {
            action = '\0';
        }


        if (!strcasecmp(w, "ApacheFS")) {
            option = USE_APACHE_FS;
        }
        else if (!strcasecmp(w, "XIncludes")) {
            option = XINCLUDES;
        }
        else if (!strcasecmp(w, "None")) {
            if (action != '\0') {
                return "Cannot combine '+' or '-' with 'None' keyword";
            }
            opts = NO_OPTIONS;
            opts_add = 0;
            opts_remove = 0;
        }
        else {
            return "Invalid TransformOption";
        }

        if (action == '\0') {
            opts |= option;
            opts_add = 0;
            opts_remove = 0;
        }
        else if (action == '+') {
            opts_add |= option;
            opts_remove &= ~option;
        }
        else {
            opts_remove |= option;
            opts_add &= ~option;
        }
    }
    if ((opts & NO_OPTIONS) && (opts & ~NO_OPTIONS)) {
        return "Cannot combine other TransformOptions keywords with 'None'";
    }
    d_cfg->incremented_opts = opts_add;
    d_cfg->decremented_opts = opts_remove;
    d_cfg->opts = opts;
    return NULL;
}

static void transform_child_init(apr_pool_t *p, server_rec *s)
{
    xmlInitParser();
    xmlInitThreads();
    exsltRegisterAll();
}

static const char *set_announce(cmd_parms *cmd, 
					   void *struct_ptr, 
					   int arg)
{
    svr_cfg *cfg = ap_get_module_config(cmd->server->module_config,
			&transform_module);

    const char *err = ap_check_cmd_context(cmd,NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
    if (err) {
	return err;
    }
    cfg->announce = arg ? 1 : 0;

    return NULL;
}

static int transform_post_config(apr_pool_t *p, apr_pool_t *log, apr_pool_t *ptemp,
					server_rec *s)
{
    svr_cfg *cfg = ap_get_module_config(s->module_config,
					&transform_module);

    /* Add version string to Apache headers */
    if (cfg->announce) {
	ap_add_version_component(p, PACKAGE_NAME"/"PACKAGE_VERSION);
    }
    return OK;
}

static void transform_hooks(apr_pool_t * p)
{
    ap_hook_post_config(transform_post_config, NULL, NULL, APR_HOOK_MIDDLE);

    ap_hook_child_init(transform_child_init, NULL, NULL, APR_HOOK_MIDDLE);

    ap_hook_post_read_request(init_notes, NULL, NULL, APR_HOOK_MIDDLE);

    ap_register_output_filter(XSLT_FILTER_NAME, transform_filter, NULL,
                              AP_FTYPE_RESOURCE);
    ap_register_output_filter(APACHEFS_FILTER_NAME, transform_apachefs_filter, NULL,
                              AP_FTYPE_RESOURCE);

};

static const command_rec transform_cmds[] = {

    AP_INIT_TAKE1("TransformSet", use_xslt, NULL, OR_ALL,
                  "Stylesheet to use"),

    AP_INIT_TAKE2("TransformCache", transform_cache_add, NULL, RSRC_CONF,
                  "URL and Path for stylesheet to preload"),

    AP_INIT_RAW_ARGS("TransformOptions", add_opts, NULL, OR_INDEXES,
                     "one or more index options [+|-][]"),

    AP_INIT_FLAG("TransformAnnounce", set_announce, NULL, RSRC_CONF,
		 "Whether to announce this module in the server header. Default: On"),
    {NULL}
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
    transform_notes *notes = ap_get_module_config(r->request_config,
                                               &transform_module);
    notes->xslt = apr_pstrdup(r->pool, name);
}

void mod_transform_XSLTDoc(request_rec * r, xmlDocPtr doc)
{
    transform_notes *notes = ap_get_module_config(r->request_config,
                                               &transform_module);
    notes->document = doc;
}
