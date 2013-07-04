# $Id: Makefile.am 49 2013-06-25 14:35:03Z rijswijk $

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/.. \
				-I$(srcdir)/../.. \
				-I$(srcdir)/../../prover \
				-I$(srcdir)/../../issuer \
				-I$(srcdir)/../../verifier \
				@CPPUNIT_CFLAGS@

check_PROGRAMS =		commontest

commontest_SOURCES =		commontest.cpp \
				typetests.h \
				typetests.cpp \
				hashtests.h \
				hashtests.cpp \
				syspartests.h \
				syspartests.cpp \
				randtests.h \
				randtests.cpp

commontest_LDADD =		../../libsilvia_convarch.la @OPENSSL_LIBS@ @CPPUNIT_LIBS@

commontest_LDFLAGS = 		-no-install

TESTS = 			commontest

EXTRA_DIST =			$(srcdir)/*.h
