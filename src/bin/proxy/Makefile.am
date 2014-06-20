# $Id$

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/../../lib/common \
				-I$(srcdir)/../../lib/verifier \
				-I$(srcdir)/../../lib/xml \
				-I$(srcdir)/../../lib/issuer \
				-I$(srcdir)/../../lib \
				@PCSC_CFLAGS@

bin_PROGRAMS =			silvia_proxy

silvia_proxy_SOURCES =	silvia_proxy.cpp

silvia_proxy_LDADD =		../../lib/libsilvia.la @OPENSSL_LIBS@ @XML_LIBS@

if BUILD_PCSC
AM_CPPFLAGS += -I$(srcdir)/../../lib/pcsc
silvia_proxy_LDADD += @PCSC_LIBS@
endif
if BUILD_NFC
AM_CPPFLAGS += -I$(srcdir)/../../lib/nfc
silvia_proxy_LDADD += @NFC_LIBS@
endif
