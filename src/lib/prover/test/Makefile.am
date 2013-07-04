# $Id: Makefile.am 54 2013-07-04 12:04:51Z rijswijk $

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/.. \
				-I$(srcdir)/../.. \
				-I$(srcdir)/../../issuer \
				-I$(srcdir)/../../common \
				-I$(srcdir)/../../verifier \
				@CPPUNIT_CFLAGS@

check_PROGRAMS =		provertest

provertest_SOURCES =		provertest.cpp \
				credgentests.h \
				credgentests.cpp \
				provetests.h \
				provetests.cpp

provertest_LDADD =		../../libsilvia_convarch.la @CPPUNIT_LIBS@ @OPENSSL_LIBS@

provertest_LDFLAGS = 		-no-install

TESTS = 			provertest

EXTRA_DIST =			$(srcdir)/*.h
