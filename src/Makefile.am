CLEANFILES = .libs/libmod_xmltransform *~

libmod_xmltransform_la_SOURCES = mod_xmltransform.c
libmod_xmltransform_la_CFLAGS = -Wall ${XML_CFLAGS}
libmod_xmltransform_la_LDFLAGS = ${XML_LDFLAGS}

lib_LTLIBRARIES = libmod_xmltransform.la 

make_so:
	@if test ! -L mod_xmltransform.so ; then ln -s .libs/libmod_xmltransform.so mod_xmltransform.so ; fi

install: make_so
	@${APXS} -i -n xmltransform mod_xmltransform.so
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
	@${APXS} -i -a -n xmltransform mod_xmltransform.so
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
