# $Id$

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/../../lib/common \
				-I$(srcdir)/../../lib/verifier \
				-I$(srcdir)/../../lib/xml \
				-I$(srcdir)/../../lib/issuer \
				-I$(srcdir)/../../lib \
				-I$(srcdir)/../../lib/stdio \
				@PCSC_CFLAGS@ \
				@XML_CFLAGS@

bin_PROGRAMS =			silvia_issuer

silvia_issuer_SOURCES =		silvia_issuer.cpp \
				silvia_issuescript.cpp \
				silvia_issuescript.h

silvia_issuer_LDADD =		../../lib/libsilvia.la @OPENSSL_LIBS@ @XML_LIBS@

if BUILD_PCSC
AM_CPPFLAGS += -I$(srcdir)/../../lib/pcsc
silvia_issuer_LDADD += @PCSC_LIBS@
endif
if BUILD_NFC
AM_CPPFLAGS += -I$(srcdir)/../../lib/nfc
silvia_issuer_LDADD += @NFC_LIBS@
endif
