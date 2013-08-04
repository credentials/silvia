# $Id$

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/../issuer \
				-I$(srcdir)/../prover \
				-I$(srcdir)/../verifier \
				-I$(srcdir)/../common \
				-I$(srcdir)/.. \
				@XML_CFLAGS@

libsilvia_xml_la_LDFLAGS =	@XML_LIBS@


noinst_LTLIBRARIES =		libsilvia_xml.la

libsilvia_xml_la_SOURCES =	silvia_idemix_xmlreader.h \
				silvia_idemix_xmlreader.cpp \
				silvia_irma_xmlreader.h \
				silvia_irma_xmlreader.cpp

libsilvia_xml_la_LIBADD =	

if BUILD_TESTS
SUBDIRS =			test
endif
