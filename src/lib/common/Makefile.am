# $Id: Makefile.am 56 2013-07-04 17:39:15Z rijswijk $

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/../common \
				-I$(srcdir)/..

noinst_LTLIBRARIES =		libsilvia_common.la

libsilvia_common_la_SOURCES =	silvia_types.h \
				silvia_types.cpp \
				silvia_hash.h \
				silvia_hash.cpp \
				silvia_parameters.h \
				silvia_parameters.cpp \
				silvia_rand.h \
				silvia_rand.cpp \
				silvia_asn1.h \
				silvia_asn1.cpp \
				silvia_timer.h \
				silvia_timer.cpp \
				silvia_bytestring.h \
				silvia_bytestring.cpp \
				silvia_apdu.h \
				silvia_apdu.cpp \
				silvia_card_channel.h

libsilvia_common_la_LIBADD =	

if BUILD_TESTS
SUBDIRS =			test
endif
