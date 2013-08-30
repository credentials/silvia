# $Id$

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/../../common \
				-I$(srcdir)/../../verifier \
				-I$(srcdir)/../../issuer \
				-I$(srcdir)/../.. \
				-I$(srcdir)/.. \
				-I/usr/include/PCSC

check_PROGRAMS =		silvia_pcsctest silvia_hsimtest silvia_issue_pcsctest silvia_issue_hsimtest

silvia_pcsctest_SOURCES =	silvia_pcsctest.cpp
silvia_hsimtest_SOURCES =	silvia_hsimtest.cpp

silvia_issue_pcsctest_SOURCES =	silvia_issue_pcsctest.cpp
silvia_issue_hsimtest_SOURCES =	silvia_issue_hsimtest.cpp

silvia_pcsctest_LDADD =		../../libsilvia_convarch.la @OPENSSL_LIBS@ @CPPUNIT_LIBS@
silvia_hsimtest_LDADD =		../../libsilvia_convarch.la @OPENSSL_LIBS@ @CPPUNIT_LIBS@
silvia_issue_pcsctest_LDADD =		../../libsilvia_convarch.la @OPENSSL_LIBS@ @CPPUNIT_LIBS@
silvia_issue_hsimtest_LDADD =		../../libsilvia_convarch.la @OPENSSL_LIBS@ @CPPUNIT_LIBS@

silvia_pcsctest_LDFLAGS = 	-no-install
silvia_hsimtest_LDFLAGS = 	-no-install
silvia_issue_pcsctest_LDFLAGS = 	-no-install
silvia_issue_hsimtest_LDFLAGS = 	-no-install

