# $Id$

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/../../common \
				-I$(srcdir)/../../verifier \
				-I$(srcdir)/../.. \
				-I$(srcdir)/..

check_PROGRAMS =		silvia_nfctest

silvia_nfctest_SOURCES =	silvia_nfctest.cpp

silvia_nfctest_LDADD =		../../libsilvia_convarch.la @OPENSSL_LIBS@ @CPPUNIT_LIBS@ @NFC_LIBS@

silvia_nfctest_LDFLAGS = 	-no-install

