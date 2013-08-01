# $Id$

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/../common \
				-I$(srcdir)/.. \
				@PCSC_CFLAGS@

noinst_LTLIBRARIES =		libsilvia_pcsc.la

libsilvia_pcsc_la_SOURCES =	silvia_card.h \
				silvia_card.cpp

libsilvia_pcsc_la_LIBADD =	

if BUILD_TESTS
SUBDIRS =			test
endif
