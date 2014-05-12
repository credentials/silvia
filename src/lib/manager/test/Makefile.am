# $Id: Makefile.am 52 2013-07-02 13:16:24Z rijswijk $

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/.. \
				-I$(srcdir)/../.. \
				-I$(srcdir)/../../prover \
				-I$(srcdir)/../../common \
				-I$(srcdir)/../../issuer \
				-I$(srcdir)/../../verifier \
				@CPPUNIT_CFLAGS@

check_PROGRAMS =		managertest

managertest_SOURCES =		managertest.cpp \
				managertests.cpp \
				managertests.h

managertest_LDADD =		../../libsilvia_convarch.la @CPPUNIT_LIBS@ @OPENSSL_LIBS@

managertest_LDFLAGS = 		-no-install

TESTS = 			managertest

EXTRA_DIST =			$(srcdir)/*.h
