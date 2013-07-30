# $Id: Makefile.am 55 2013-07-04 14:19:14Z rijswijk $

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/../common \
				-I$(srcdir)/..

noinst_LTLIBRARIES =		libsilvia_verifier.la

libsilvia_verifier_la_SOURCES =	silvia_verifier.h \
				silvia_verifier.cpp

libsilvia_verifier_la_LIBADD =	

if BUILD_TESTS
SUBDIRS =			test
endif
