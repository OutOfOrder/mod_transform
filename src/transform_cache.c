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


#include "mod_transform_private.h"

void *transform_cache_get(svr_cfg * sconf, const char *descriptor)
{
    transform_xslt_cache *p;
    if (!descriptor)
        return 0;

    for (p = sconf->data; p; p = p->next) {
        if (!strcmp(descriptor, p->id)) {
            return p->transform;
        }
    }

    return 0;
}

const char *transform_cache_add(cmd_parms * cmd, void *cfg,
                                            const char *url, const char *path)
{
    svr_cfg *conf = ap_get_module_config(cmd->server->module_config,
                                         &transform_module);
    xsltStylesheetPtr xslt = xsltParseStylesheetFile(path);
    if (url && path && xslt) {
        transform_xslt_cache *me =
            apr_palloc(cmd->pool, sizeof(transform_xslt_cache));
        me->id = apr_pstrdup(cmd->pool, url);
        me->transform = xslt;
        me->next = conf->data;
        conf->data = me;
        ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, cmd->pool,
                      "mod_transform: Cached Precompiled XSL: %s", url);
        return NULL;
    }
    else {
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, cmd->pool,
                      "mod_transform: Error fetching or compiling XSL from: %s",
                      path);
        return "Error trying to precompile XSLT";
    }
}

apr_status_t transform_cache_free(void *conf)
{
    transform_xslt_cache *p;
    svr_cfg *cfg = conf;
    for (p = cfg->data; p; p = p->next) {
        xsltFreeStylesheet(p->transform);
    }
    return APR_SUCCESS;
}

