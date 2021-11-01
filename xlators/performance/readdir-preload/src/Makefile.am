xlator_LTLIBRARIES = readdir-preload.la
xlatordir = $(libdir)/glusterfs/$(PACKAGE_VERSION)/xlator/performance

readdir_preload_la_LDFLAGS = -module -avoid-version

readdir_preload_la_SOURCES = readdir-preload.c
readdir_preload_la_LIBADD = $(top_builddir)/libglusterfs/src/libglusterfs.la

noinst_HEADERS = readdir-preload.h readdir-preload-mem-types.h readdir-preload-messages.h

AM_CPPFLAGS = $(GF_CPPFLAGS) -I$(top_srcdir)/libglusterfs/src

AM_CFLAGS = -Wall $(GF_CFLAGS)

CLEANFILES =
