# $Id$

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/../../common \
				-I$(srcdir)/../../verifier \
				-I$(srcdir)/../.. \
				-I$(srcdir)/.. \
				-I/usr/include/PCSC

check_PROGRAMS =		silvia_pcsctest

silvia_pcsctest_SOURCES =	silvia_pcsctest.cpp

silvia_pcsctest_LDADD =		../../libsilvia_convarch.la @OPENSSL_LIBS@ @CPPUNIT_LIBS@

silvia_pcsctest_LDFLAGS = 	-no-install

