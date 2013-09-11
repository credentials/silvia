# $Id$

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/../../common \
				-I$(srcdir)/../../verifier \
				-I$(srcdir)/../.. \
				-I$(srcdir)/.. \
				-I/usr/include/PCSC

check_PROGRAMS =		silvia_pcsctest \
				test_nfctag

silvia_pcsctest_SOURCES =	silvia_pcsctest.cpp

silvia_pcsctest_LDADD =		../../libsilvia_convarch.la @OPENSSL_LIBS@ @CPPUNIT_LIBS@

silvia_pcsctest_LDFLAGS = 	-no-install

test_nfctag_SOURCES =		test_nfctag.cpp

test_nfctag_LDADD =		../../libsilvia_convarch.la @OPENSSL_LIBS@ @CPPUNIT_LIBS@

test_nfctag_LDFLAGS = 		-no-install

