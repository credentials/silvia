# $Id: Makefile.am 42 2013-06-20 12:47:04Z rijswijk $

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

# We can build verifier and issuer with stdio
SUBDIRS = keygen \
          manager \
		  verifier \
		  issuer

# Only build the command line verifier if we have PC/SC or NFC and XML support!
if BUILD_XMLCFG
if BUILD_PCSC
SUBDIRS += proxy
else
if BUILD_NFC
SUBDIRS += proxy
endif
endif
endif
# And only build the command line MULTOS application loader if we have PC/SC support!
if BUILD_PCSC
SUBDIRS += loader
endif
