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
 
#ifndef _MOD_TRANSFORM_H
#define _MOD_TRANSFORM_H
 
#include <httpd.h>
#include <libxml/tree.h>
#include <libxslt/xslt.h>

#ifdef __cplusplus
extern "C" {
#endif
 
void mod_transform_set_XSLT(request_rec* r, const char* name) ;
void mod_transform_XSLTDoc(request_rec* r, xmlDocPtr doc) ;

#ifdef __cplusplus
}
#endif
 
#endif
