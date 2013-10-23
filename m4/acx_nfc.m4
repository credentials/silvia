# $Id$

AC_DEFUN([ACX_NFC],[
	nfc_found=no
	PKG_CHECK_MODULES([NFC], [libnfc >= 1.7.0], [
		AC_CHECK_LIB(nfc, nfc_open, [
			AM_CONDITIONAL([BUILD_NFC], true)
			AC_DEFINE(WITH_NFC, 1, [build with NFC support])
			nfc_found=yes
		], [
			AC_MSG_WARN([broken libnfc found, building without NFC support])
		])
	], [AC_MSG_WARN([
======================================================================
You configured Silvia to build with NFC support but a suitable version
of libnfc was not found. Note that the required minimum version of
libnfc (1.7.0-rc8 or up) was not released when this release of Silvia
was under development; this means you may have to build and install
libnfc directly from the code repository on the libnfc.org website.

For more information on building libnfc from the source repository,
please see:

http://nfc-tools.org/index.php?title=Libnfc#Development_version

IMPORTANT NOTE: if you build libnfc from source, make sure you update
                the version number in the file "configure.ac" in the
                root directory of the code from the repository; change
                the version information on line 4 to say at least
                1.7.0-rc8

Proceeding to build Silvia WITHOUT NFC SUPPORT
======================================================================])
	])
])
