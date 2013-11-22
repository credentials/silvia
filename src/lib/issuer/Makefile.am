# $Id: Makefile.am 52 2013-07-02 13:16:24Z rijswijk $

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/../common \
				-I$(srcdir)/..

noinst_LTLIBRARIES =		libsilvia_issuer.la

libsilvia_issuer_la_SOURCES =	silvia_issuer_keygen.cpp \
				silvia_issuer_keygen.h \
				silvia_issue_spec.cpp \
				silvia_issue_spec.h \
				silvia_irma_issuer.cpp \
				silvia_irma_issuer.h \
				silvia_issuer.cpp \
				silvia_issuer.h

libsilvia_issuer_la_LIBADD =	

pkginclude_HEADERS =		silvia_issuer.h \
				silvia_irma_issuer.h

if BUILD_TESTS
SUBDIRS =			test
endif
