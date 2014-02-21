# $Id$

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/../common \
				-I$(srcdir)/.. \
				@NFC_CFLAGS@

noinst_LTLIBRARIES =		libsilvia_nfc.la

libsilvia_nfc_la_SOURCES =	silvia_nfc_card.h \
				silvia_nfc_card.cpp

libsilvia_nfc_la_LIBADD =	

pkginclude_HEADERS =		silvia_nfc_card.h


if BUILD_TESTS
SUBDIRS =			test
endif
