/**
 *    Copyright (c) 2007 Christian Parpart
 *    Authors:    Christian Parpart <trapni at gentoo.org>
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
 *
 *  \note This is a mod_transform plugin. Activate it in your config as follows:
 *        <pre>TransformLoadPlugin http</pre>
 */

#include <mod_transform.h>

#include <apreq2/apreq_module_apache2.h>

#include <httpd.h>
#include <http_log.h>
#include <util_filter.h>

#include <libxslt/extensions.h>
#include <libxslt/xsltutils.h>
#include <libxml/xpathInternals.h>

#include <string.h>
#include <stdlib.h>

// XXX print some debug output into log stream
//#define _DEBUG (1)

const char *HTTP_NS = "http://opensource.surakware.com/wiki/apache";

const apr_table_t *FGetArgs = NULL;
const apr_table_t *FPostArgs = NULL;
ap_filter_t *FFilter = NULL;

/* {{{ XPath functions */
/*! \brief string http:remote-ip(); 
 * 
 * returns the remote IP address of the connecting client
 */
static void httpRemoteIP(xmlXPathParserContextPtr ctxt, int nargs) {
	if (nargs != 0) {
		xmlXPathSetArityError(ctxt);
		return;
	}

	xmlXPathReturnString(ctxt, xmlStrdup((xmlChar *)FFilter->r->connection->remote_ip));
}

/*! \brief string http:remote-port();
 *
 * returns the remote TCP port number of the connecting client
 */
static void httpRemotePort(xmlXPathParserContextPtr ctxt, int nargs) {
	if (nargs != 0) {
		xmlXPathSetArityError(ctxt);
		return;
	}

	xmlXPathReturnNumber(ctxt, FFilter->r->connection->remote_addr->port);
}

/*! \brief string http:request-header(string name);
 *
 * returns any kind of HTTP request header identified by \p name.
 */
static void httpRequestHeader(xmlXPathParserContextPtr ctxt, int nargs) {
	xmlChar *name;
	xmlChar *value;

	if (nargs != 1) {
		xmlXPathSetArityError(ctxt);
		return;
	}

	name = xmlXPathPopString(ctxt);
	value = (xmlChar *)apr_table_get(FFilter->r->headers_in, (const char *)name);

	if (value != NULL)
		value = xmlStrdup(value);
	else
		value = xmlStrdup((xmlChar *)"");

	xmlXPathReturnString(ctxt, value);
}

/*! \brief string http:get(string key);
 *
 * returns an HTTP request GET/POST argument identified by key.
 *
 * \note GET precedes POST arguments.
 */
static void httpGet(xmlXPathParserContextPtr ctxt, int nargs) {
	xmlChar *key;
	xmlChar *value = NULL;

	if (nargs != 1) {
		xmlXPathSetArityError(ctxt);
		return;
	}

	key = xmlXPathPopString(ctxt);

	if (FGetArgs) {
		value = (xmlChar *)apr_table_get(FGetArgs, (const char *)key);
	}
	if (!value && FPostArgs) {
		value = (xmlChar *)apr_table_get(FPostArgs, (const char *)key);
	}

	if (value)
		value = xmlStrdup(value);
	else
		value = xmlStrdup((xmlChar *)"");

	xmlXPathReturnString(ctxt, value);
}
/* }}} */

/* {{{ mod_transform hooks */
static void child_init(apr_pool_t *p, server_rec *s) {
	xsltRegisterExtModuleFunction((const xmlChar *)"get", (const xmlChar *)HTTP_NS, httpGet);
	xsltRegisterExtModuleFunction((const xmlChar *)"request-header", (const xmlChar *)HTTP_NS, httpRequestHeader);
	xsltRegisterExtModuleFunction((const xmlChar *)"remote-ip", (const xmlChar *)HTTP_NS, httpRemoteIP);
	xsltRegisterExtModuleFunction((const xmlChar *)"remote-port", (const xmlChar *)HTTP_NS, httpRemotePort);
}

static void filter_init(ap_filter_t *f) {
	apreq_handle_apache2(f->r); /* XXX for future use... most probabely */
}

#ifdef _DEBUG
static int dump_table(void *data, const char *key, const char *value) {
	struct ap_filter_t *f = (struct ap_filter_t *)data;

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, f->r, "(%s)=(%s)", key, value);

	return 1;
}
#endif

static void transform_run_begin(ap_filter_t *f) {
	apreq_handle_t *apreq;

	apreq = apreq_handle_apache2(f->r);

	apreq_args(apreq, &FGetArgs);

#ifdef _DEBUG
	if (FGetArgs != NULL) {
		apr_table_do(&dump_table, f, FGetArgs, NULL);
	} else {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, f->r, "%s", "no GET args passed.");
	}
#endif

	apreq_body(apreq, &FPostArgs);

#ifdef _DEBUG
	if (FPostArgs != NULL) {
		apr_table_do(&dump_table, f, FPostArgs, NULL);
	} else {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, f->r, "%s", "no POST args passed.");
	}
#endif

	FFilter = f;
}

static void transform_run_end(ap_filter_t *f) {
	FGetArgs = NULL;
	FPostArgs = NULL;
	FFilter = NULL;
}
/* }}} */

/* {{{ mod_transform plugin entry table */
mod_transform_plugin_t http_plugin = {
	NULL, /* &plugin_init, */
	NULL, /* &post_config, */
	&child_init,
	&filter_init,
	&transform_run_begin,
	&transform_run_end
};
/* }}} */
