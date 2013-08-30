# $Id$

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/../../lib/common \
				-I$(srcdir)/../../lib/verifier \
				-I$(srcdir)/../../lib/xml \
				-I$(srcdir)/../../lib \
				@PCSC_CFLAGS@

bin_PROGRAMS =			silvia_verifier

silvia_verifier_SOURCES =	silvia_verifier.cpp

silvia_verifier_LDADD =		../../lib/libsilvia.la @OPENSSL_LIBS@ @XML_LIBS@

if BUILD_PCSC
AM_CPPFLAGS += -I$(srcdir)/../../lib/pcsc
silvia_verifier_LDADD += @PCSC_LIBS@
endif
if BUILD_NFC
AM_CPPFLAGS += -I$(srcdir)/../../lib/nfc
silvia_verifier_LDADD += @NFC_LIBS@
endif
