AUTOMAKE_OPTIONS = foreign dist-bzip2

EXTRA_DIST = m4/libxslt.m4 \
	m4/libxml.m4 \
	m4/apache.m4 \
	m4/apache_test.m4 \
	m4/outoforder.m4 \
	include/mod_transform.h \
	include/mod_transform_private.h \
	TODO \
	README

SUBDIRS = src

TODO: TODO.in
	./gen_todo.pl
