# $Id$

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/.. \
				-I$(srcdir)/../.. \
				-I$(srcdir)/../../issuer \
				-I$(srcdir)/../../verifier \
				-I$(srcdir)/../../common \
				-I$(srcdir)/../../prover \
				@CPPUNIT_CFLAGS@

check_PROGRAMS =		xmltest

xmltest_SOURCES =		xmltest.cpp \
				xmltests.h \
				xmltests.cpp

xmltest_LDADD =			../../libsilvia_convarch.la @CPPUNIT_LIBS@ @OPENSSL_LIBS@ @XML_LIBS@

xmltest_LDFLAGS = 		-no-install

TESTS = 			xmltest

EXTRA_DIST =			$(srcdir)/*.h
