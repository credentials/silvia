# $Id: Makefile.am 57 2013-07-04 18:07:24Z rijswijk $

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/.. \
				-I$(srcdir)/../common \
				-I$(srcdir)/../prover \
				-I$(srcdir)/../issuer \
				-I$(srcdir)/../verifier \
				@CPPUNIT_CFLAGS@

check_PROGRAMS =		silviatest

silviatest_SOURCES =		silviatest.cpp \
				issuetests.cpp \
				issuetests.h \
				proveverifytests.cpp \
				proveverifytests.h

silviatest_LDADD =		../libsilvia_convarch.la @CPPUNIT_LIBS@ @OPENSSL_LIBS@

silviatest_LDFLAGS = 		-no-install

TESTS = 			silviatest
