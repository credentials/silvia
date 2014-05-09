# $Id: Makefile.am 52 2013-07-02 13:16:24Z rijswijk $

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/.. \
				-I$(srcdir)/../.. \
				-I$(srcdir)/../../prover \
				-I$(srcdir)/../../common \
				-I$(srcdir)/../../verifier \
				@CPPUNIT_CFLAGS@

check_PROGRAMS =		issuertest

issuertest_SOURCES =		issuertest.cpp \
				keygentests.cpp \
				keygentests.h \
				issuetests.cpp \
				issuetests.h

issuertest_LDADD =		../../libsilvia_convarch.la @CPPUNIT_LIBS@ @OPENSSL_LIBS@

issuertest_LDFLAGS = 		-no-install

TESTS = 			issuertest

EXTRA_DIST =			$(srcdir)/*.h
