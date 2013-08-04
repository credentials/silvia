# $Id$

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/../../lib/common \
				-I$(srcdir)/../../lib/verifier \
				-I$(srcdir)/../../lib/xml \
				-I$(srcdir)/../../lib/pcsc \
				-I$(srcdir)/../../lib \
				@PCSC_CFLAGS@

bin_PROGRAMS =			silvia_verifier

silvia_verifier_SOURCES =	silvia_verifier.cpp

silvia_verifier_LDADD =		../../lib/libsilvia.la @OPENSSL_LIBS@ @XML_LIBS@ @PCSC_LIBS@
