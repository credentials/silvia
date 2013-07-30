# $Id: Makefile.am 54 2013-07-04 12:04:51Z rijswijk $

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/../common \
				-I$(srcdir)/..

noinst_LTLIBRARIES =		libsilvia_prover.la

libsilvia_prover_la_SOURCES =	silvia_prover_credgen.h \
				silvia_prover_credgen.cpp \
				silvia_prover.h \
				silvia_prover.cpp

libsilvia_prover_la_LIBADD =	

if BUILD_TESTS
SUBDIRS =			test
endif
