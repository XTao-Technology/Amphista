xlator_LTLIBRARIES = dirstat-cache.la
xlatordir = $(libdir)/glusterfs/$(PACKAGE_VERSION)/xlator/performance
dirstat_cache_la_LDFLAGS = -module -avoid-version

dirstat_cache_la_SOURCES = dirstat-cache.c
dirstat_cache_la_LIBADD = $(top_builddir)/libglusterfs/src/libglusterfs.la

noinst_HEADERS = dirstat-cache.h dsc-mem-types.h

AM_CPPFLAGS = $(GF_CPPFLAGS) -I$(top_srcdir)/libglusterfs/src \
	-I$(CONTRIBDIR)/rbtree

AM_CFLAGS = -Wall $(GF_CFLAGS)

CLEANFILES =
