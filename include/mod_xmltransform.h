#ifndef _MOD_XMLTRANSFORM_H
#define _MOD_XMLTRANSFORM_H
 
#include <httpd.h>
#include <libxml/tree.h>

#ifdef __cplusplus
extern "C" {
#endif
 
void mod_xmltransform_set_XSLT(request_rec* r, const char* name) ;
void mod_xmltransform_XSLTDoc(request_rec* r, xmlDocPtr doc) ;

#ifdef __cplusplus
}
#endif
 
#endif
