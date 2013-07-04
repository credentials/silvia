# $Id: Makefile.am 55 2013-07-04 14:19:14Z rijswijk $

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/.. \
				-I$(srcdir)/../.. \
				-I$(srcdir)/../../issuer \
				-I$(srcdir)/../../common \
				-I$(srcdir)/../../prover \
				@CPPUNIT_CFLAGS@

check_PROGRAMS =		verifiertest

verifiertest_SOURCES =		verifiertest.cpp \
				verifytests.h \
				verifytests.cpp

verifiertest_LDADD =		../../libsilvia_convarch.la @CPPUNIT_LIBS@ @OPENSSL_LIBS@

verifiertest_LDFLAGS = 		-no-install

TESTS = 			verifiertest

EXTRA_DIST =			$(srcdir)/*.h
