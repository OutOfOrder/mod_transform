/**
 *    Copyright (c) 2002, WebThing Ltd
 *    Copyright (c) 2004 Edward Rudd
 *    Copyright (c) 2004 Paul Querna
 *    Authors:    Nick Kew <nick webthing.com>
 *                Edward Rudd <eddie at omegaware dot com>
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

#ifndef _MOD_TRANSFORM_PRIVATE_H
#define _MOD_TRANSFORM_PRIVATE_H

#include "mod_transform.h"

#define XSLT_FILTER_NAME "XSLT"

#define APACHEFS_FILTER_NAME "transform_store_brigade"

#include "http_config.h"
#include "http_protocol.h"
#include "http_core.h"
#include "http_log.h"
#include "http_request.h"
#include "apr_buckets.h"
#include "apr_strings.h"
#include "apr_uri.h"
#include "apr_tables.h"

#include <libxml/globals.h>
#include <libxml/threads.h>
#include <libxml/xinclude.h>
#include <libxml/xmlIO.h>
#include <libxslt/xsltutils.h>
#include <libxslt/transform.h>
#include <libexslt/exslt.h>

/* Did I mention auto*foo sucks? */
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#include "mod_transform_config.h"

extern module AP_MODULE_DECLARE_DATA transform_module;

/* TransformOptions */
#define NO_OPTIONS          (1 <<  0)
#define USE_APACHE_FS       (1 <<  1)
#define XINCLUDES           (1 <<  2)

/* Static Style Sheet Caching */
typedef struct transform_xslt_cache
{
    const char *id;
    xsltStylesheetPtr transform;
    struct transform_xslt_cache *next;
}
transform_xslt_cache;

typedef struct svr_cfg
{
    transform_xslt_cache *data;
    int announce;
}
svr_cfg;

typedef struct dir_cfg
{
    const char *xslt;
    const char *default_xslt;
    apr_int32_t opts;
    apr_int32_t incremented_opts;
    apr_int32_t decremented_opts;
}
dir_cfg;

typedef struct
{
    const char *xslt;
    xmlDocPtr document;
}
transform_notes;


typedef struct
{
    ap_filter_t *next;
    apr_bucket_brigade *bb;
}
transform_xmlio_output_ctx;

int transform_xmlio_output_write(void *context, const char *buffer, int len);
int transform_xmlio_output_close(void *context);

typedef struct
{
    ap_filter_t *f;
    apr_pool_t *p;
    request_rec *rr;
    apr_bucket_brigade *bb;
}
transform_xmlio_input_ctx;

apr_status_t transform_apachefs_filter(ap_filter_t * f,
                                       apr_bucket_brigade * bb);

xmlParserInputBufferPtr transform_get_input(const char *URI,
                                            xmlCharEncoding enc);



void *transform_cache_get(svr_cfg * sconf, const char *descriptor);
apr_status_t transform_cache_free(void *conf);
const char *transform_cache_add(cmd_parms * cmd, void *cfg, const char *url,
                                const char *path);

#endif /* _MOD_TRANSFORM_PRIVATE_H */
