CLEANFILES = .libs/libmod_transform *~

libmod_transform_la_SOURCES = mod_transform.c
libmod_transform_la_CFLAGS = -Wall ${XSLT_CFLAGS} ${MODULE_CFLAGS}
libmod_transform_la_LDFLAGS = ${XSLT_LIBS}

lib_LTLIBRARIES = libmod_transform.la 

make_so:
	@if test ! -L mod_transform.so ; then ln -s .libs/libmod_transform.so mod_transform.so ; fi

clean:
	rm -fr .libs
	rm -f *.o *.lo *.la
	rm -f mod_transform.so

install: make_so
	@${APXS_BIN} -i -n transform mod_transform.so
	cp ../include/mod_transform.h ${AP_INCLUDEDIR}
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

activate: make_so
	@${APXS_BIN} -i -a -n transform mod_transform.so
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
