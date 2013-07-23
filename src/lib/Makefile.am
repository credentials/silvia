# $Id: Makefile.am 57 2013-07-04 18:07:24Z rijswijk $

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/issuer \
				-I$(srcdir)/prover \
				-I$(srcdir)/verifier \
				-I$(srcdir)/common

lib_LTLIBRARIES =		libsilvia.la

libsilvia_la_SOURCES =		
libsilvia_la_LIBADD =		issuer/libsilvia_issuer.la \
				prover/libsilvia_prover.la \
				verifier/libsilvia_verifier.la \
				common/libsilvia_common.la \
				pcsc/libsilvia_pcsc.la
libsilvia_la_LDFLAGS =		-version-info @VERSION_INFO@ \
				-avoid-version -module \
				@OPENSSL_LIBS@

# Create a convenience library from all the other convenience libraries; this is
# necessary to resolve circular dependencies when statically linking the test
# executables
noinst_LTLIBRARIES =		libsilvia_convarch.la

libsilvia_convarch_la_SOURCES =

libsilvia_convarch_la_LIBADD =	$(libsilvia_la_LIBADD)

SUBDIRS = 			issuer \
				prover \
				verifier \
				common \
				pcsc \
				test

EXTRA_DIST =			$(srcdir)/*.h
