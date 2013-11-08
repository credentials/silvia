# $Id$

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/../../lib/common \
				-I$(srcdir)/../../lib \
				@PCSC_CFLAGS@

bin_PROGRAMS =			silvia_loader

silvia_loader_SOURCES =		silvia_loader.cpp

silvia_loader_LDADD =		../../lib/libsilvia.la @OPENSSL_LIBS@ @XML_LIBS@

if BUILD_PCSC
AM_CPPFLAGS += -I$(srcdir)/../../lib/pcsc
silvia_loader_LDADD += @PCSC_LIBS@
endif
if BUILD_NFC
AM_CPPFLAGS += -I$(srcdir)/../../lib/nfc
silvia_loader_LDADD += @NFC_LIBS@
endif
