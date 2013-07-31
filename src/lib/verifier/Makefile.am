# $Id: Makefile.am 55 2013-07-04 14:19:14Z rijswijk $

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/../common \
				-I$(srcdir)/..

noinst_LTLIBRARIES =		libsilvia_verifier.la

libsilvia_verifier_la_SOURCES =	silvia_verifier.h \
				silvia_verifier.cpp \
				silvia_verifier_spec.h \
				silvia_verifier_spec.cpp \
				silvia_irma_verifier.h \
				silvia_irma_verifier.cpp

libsilvia_verifier_la_LIBADD =	

if BUILD_TESTS
SUBDIRS =			test
endif
