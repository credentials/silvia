# $Id$

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/../../lib/common \
				-I$(srcdir)/../../lib/verifier \
				-I$(srcdir)/../../lib/manager \
				-I$(srcdir)/../../lib/xml \
				-I$(srcdir)/../../lib/issuer \
				-I$(srcdir)/../../lib \
				@PCSC_CFLAGS@ \
				@XML_CFLAGS@

bin_PROGRAMS =			silvia_manager

silvia_manager_SOURCES =		silvia_manager.cpp

silvia_manager_LDADD =		../../lib/libsilvia.la @OPENSSL_LIBS@ @XML_LIBS@

if BUILD_PCSC
AM_CPPFLAGS += -I$(srcdir)/../../lib/pcsc
silvia_manager_LDADD += @PCSC_LIBS@
endif
if BUILD_NFC
AM_CPPFLAGS += -I$(srcdir)/../../lib/nfc
silvia_manager_LDADD += @NFC_LIBS@
endif
