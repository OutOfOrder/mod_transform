CLEANFILES = .libs/libmod_transform *~

libmod_transform_la_SOURCES = mod_transform.c
libmod_transform_la_CFLAGS = -Wall ${XSLT_CFLAGS}
libmod_transform_la_LDFLAGS = ${XSLT_LIBS}

lib_LTLIBRARIES = libmod_transform.la 

make_so:
	@if test ! -L mod_transform.so ; then ln -s .libs/libmod_transform.so mod_transform.so ; fi

install: make_so
	@${APXS} -i -n transform mod_transform.so
	@echo ""
	@echo ""
	@echo "***********************************************"
	@echo ""
	@echo "   Please read the documentation at            "
	@echo "   http://mod-auth.sourceforge.net/docs/ for   "
	@echo "   details on configuration of this module     "
	@echo ""
	@echo "***********************************************"
	@echo ""

activate: make_so
	@${APXS} -i -a -n transform mod_transform.so
	@echo ""
	@echo ""
	@echo "***********************************************"
	@echo ""
	@echo "   Please read the documentation at            "
	@echo "   http://mod-auth.sourceforge.net/docs/ for   "
	@echo "   details on configuration of this module     "
	@echo ""
	@echo "***********************************************"
	@echo ""
