#ifndef MODXML_GNOME_XSLT
#define MODXML_GNOME_XSLT
 
#include <httpd.h>
#include <libxml/tree.h>

#ifdef __cplusplus
extern "C" {
#endif
 
void modxmlGnomeSetXSLT(request_rec* r, const char* name) ;
void modxmlGnomeXSLTDoc(request_rec* r, xmlDocPtr doc) ;

#ifdef __cplusplus
}
#endif
 
#endif
