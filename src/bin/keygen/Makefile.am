# $Id$

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/../../lib/common \
				-I$(srcdir)/../../lib/issuer \
				-I$(srcdir)/../../lib

bin_PROGRAMS =			silvia_keygen

silvia_keygen_SOURCES =		silvia_keygen.cpp

silvia_keygen_LDADD =		../../lib/libsilvia.la @OPENSSL_LIBS@
