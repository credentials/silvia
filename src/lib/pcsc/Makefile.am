# $Id$

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/../common \
				-I$(srcdir)/.. \
				@PCSC_CFLAGS@

noinst_LTLIBRARIES =		libsilvia_pcsc.la

libsilvia_pcsc_la_SOURCES =	silvia_pcsc_card.h \
				silvia_pcsc_card.cpp

libsilvia_pcsc_la_LIBADD =	

pkginclude_HEADERS =		silvia_pcsc_card.h

if BUILD_TESTS
SUBDIRS =			test
endif
