# $Id: Makefile.am 42 2013-06-20 12:47:04Z rijswijk $

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

SUBDIRS = keygen

# Only build the command line verifier if we have PC/SC and XML support!
if BUILD_PCSC
if BUILD_XMLCFG
SUBDIRS += verifier
endif
endif
