# $Id: Makefile.am 52 2013-07-02 13:16:24Z rijswijk $

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/../common \
				-I$(srcdir)/..

noinst_LTLIBRARIES =		libsilvia_manager.la

libsilvia_manager_la_SOURCES =	silvia_irma_manager.cpp \
				silvia_irma_manager.h 

libsilvia_manager_la_LIBADD =	

pkginclude_HEADERS =		silvia_irma_manager.h


if BUILD_TESTS
SUBDIRS =			test
endif
