# $Id: Makefile.am 57 2013-07-04 18:07:24Z rijswijk $

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/issuer \
				-I$(srcdir)/prover \
				-I$(srcdir)/verifier \
				-I$(srcdir)/manager \
				-I$(srcdir)/common

lib_LTLIBRARIES =		libsilvia.la

libsilvia_la_SOURCES =		
libsilvia_la_LIBADD =		issuer/libsilvia_issuer.la \
				prover/libsilvia_prover.la \
				manager/libsilvia_manager.la \
				verifier/libsilvia_verifier.la \
				common/libsilvia_common.la 

libsilvia_la_LDFLAGS =		-version-info @VERSION_INFO@ \
				@OPENSSL_LIBS@

# Create a convenience library from all the other convenience libraries; this is
# necessary to resolve circular dependencies when statically linking the test
# executables
noinst_LTLIBRARIES =		libsilvia_convarch.la

libsilvia_convarch_la_SOURCES =

libsilvia_convarch_la_LIBADD =	$(libsilvia_la_LIBADD)

SUBDIRS = 			issuer \
				prover \
				verifier \
				manager \
				common

# Process optional components
if BUILD_PCSC
AM_CPPFLAGS += 			-I$(srcdir)/pcsc
libsilvia_la_LIBADD +=		pcsc/libsilvia_pcsc.la
SUBDIRS +=			pcsc
libsilvia_la_LDFLAGS +=		@PCSC_LIBS@
endif

if BUILD_NFC
AM_CPPFLAGS +=			-I$(srcdir)/nfc
libsilvia_la_LIBADD +=		nfc/libsilvia_nfc.la
SUBDIRS +=			nfc
libsilvia_la_LDFLAGS +=		@NFC_LIBS@
endif

if BUILD_XMLCFG
AM_CPPFLAGS +=			-I$(srcdir)/xml
libsilvia_la_LIBADD +=		xml/libsilvia_xml.la
libsilvia_la_LDFLAGS +=		@XML_LIBS@
SUBDIRS +=			xml
endif

if BUILD_TESTS
SUBDIRS +=			test
endif

