mod_transform_la_SOURCES = mod_transform.c transform_io.c transform_cache.c
mod_transform_la_CFLAGS = -Wall -I${top_srcdir}/include ${XSLT_CFLAGS} ${MODULE_CFLAGS}
mod_transform_la_LDFLAGS =  -rpath ${AP_LIBEXECDIR} -module -avoid-version ${XSLT_LIBS} -lexslt

mod_LTLIBRARIES = mod_transform.la 
moddir=${AP_LIBEXECDIR}

install: install-am
	rm -f $(DESTDIR)${AP_LIBEXECDIR}/mod_transform.a
	rm -f $(DESTDIR)${AP_LIBEXECDIR}/mod_transform.la
	mkdir -p $(DESTDIR)/${AP_INCLUDEDIR}
	cp ../include/mod_transform.h $(DESTDIR)/${AP_INCLUDEDIR}
	@echo ""
	@echo ""
	@echo "***********************************************"
	@echo ""
	@echo "   Please read the documentation at            "
	@echo "   http://www.outoforder.cc/projects/apache/mod_transform/ "
	@echo "   for details on configuration of this module     "
	@echo ""
	@echo "***********************************************"
	@echo ""
