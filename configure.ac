dnl
dnl $Id: configure.ac 57 2013-07-04 18:07:24Z rijswijk $
dnl

################################################################################
# Version information                                                          #
################################################################################

# Program version

define([SILVIA_VERSION_MAJOR], [0])
define([SILVIA_VERSION_MINOR], [2])
define([SILVIA_VERSION_BUILDREV], [0])
define([PACKAGE_SUFFIX], [])

# Library version

# Code changed:                      SILVIA_VERSION_REVISION++
# Interface added/removed/changed:   SILVIA_VERSION_CURRENT++, SILVIA_VERSION_REVISION=0
# Interface added:                   SILVIA_VERSION_AGE++
# Interface removed:                 SILVIA_VERSION_AGE=0

define([SILVIA_VERSION_CURRENT], [0])
define([SILVIA_VERSION_AGE], [0])
define([SILVIA_VERSION_REVISION], [1])

################################################################################
# Configuration functions                                                      #
################################################################################

# Init
AC_PREREQ(2.61)
AC_INIT([silvia],[SILVIA_VERSION_MAJOR.SILVIA_VERSION_MINOR.SILVIA_VERSION_BUILDREV[]PACKAGE_SUFFIX])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_SRCDIR([src/Makefile.am])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)
ACX_PREFIXHACK

# Version info for the library
VERSION_INFO="SILVIA_VERSION_CURRENT:SILVIA_VERSION_REVISION:SILVIA_VERSION_AGE"
AC_SUBST(VERSION_INFO)

# Checks for compilers and other programs
AC_PROG_CC_C99
AC_PROG_CXX

AC_PROG_INSTALL

# Compiler flags
ACX_PEDANTIC
ACX_STRICT

# Libtool settings
AC_DISABLE_STATIC
AC_PROG_LIBTOOL
PKG_PROG_PKG_CONFIG

# Log level
AC_ARG_WITH(
	[loglevel],
	[AS_HELP_STRING([--with-loglevel=INT],[The log level. 0=No log 1=Error 2=Warning 3=Info 4=Debug (default INT=3)])],
	[SILVIA_LOGLEVEL="$withval"],
	[SILVIA_LOGLEVEL=3]
)

################################################################################
# Optional components
################################################################################

# Direct PC/SC support
AC_ARG_WITH(
	[pcsc],
	AC_HELP_STRING([--with-pcsc], [Build the library with built-in PC/SC smart card support; requires PC/SC lite >= 1.4.0]),
	[build_pcsc="${withval}"],
	[build_pcsc="yes"]
)

AC_MSG_CHECKING(if building with PC/SC support)
if test "x${build_pcsc}" = "xyes" ; then
	AC_MSG_RESULT(yes)
	case "${host}" in
		*-*-darwin*)
			AC_CHECK_HEADER(/System/Library/Frameworks/PCSC.framework/Headers/winscard.h, , AC_MSG_ERROR([Mac OS X PC/SC framework required]))
			AC_CHECK_FILE(/System/Library/Frameworks/PCSC.framework/PCSC, , AC_MSG_ERROR([Mac OS X PC/SC framework required]))
			PCSC_CFLAGS="-I/System/Library/Frameworks/PCSC.framework/Headers"
			PCSC_LIBS="-framework PCSC"
			;;
		*)
			PKG_CHECK_MODULES([PCSC], [libpcsclite >= 1.4.0], , AC_MSG_ERROR([PC/SC lite 1.4.0 or newer not found]))
			AC_CHECK_LIB(pcsclite, SCardConnect)
			;;
	esac
	AC_DEFINE(WITH_PCSC, 1, [build with PC/SC support])
else
	AC_MSG_RESULT(no)
fi
AM_CONDITIONAL([BUILD_PCSC], [test "x${build_pcsc}" = "xyes"])

# Direct NFC support through libnfc
AC_ARG_WITH(
	[nfc],
	AC_HELP_STRING([--with-nfc], [Build the library with built-in NFC support; requires libnfc >= 1.7.0]),
	[build_nfc="${withval}"],
	[build_nfc="yes"]
)

AC_MSG_CHECKING(if building with NFC support)
if test "x${build_nfc}" = "xyes" ; then
	AC_MSG_RESULT(yes)
	ACX_NFC
else
	AC_MSG_RESULT(no)
fi
AM_CONDITIONAL([BUILD_NFC], [test "x${nfc_found}" = "xyes"])

# Build unit test cases
AC_ARG_WITH(
	[tests],
	AC_HELP_STRING([--with-tests], [Build the unit tests (use 'make check' to run); requires CPPUnit]),
	[build_tests="${withval}"],
	[build_tests="yes"]
)

AC_MSG_CHECKING(if building with unit tests)
if test "x${build_tests}" = "xyes" ; then
	AC_MSG_RESULT(yes)
	PKG_CHECK_MODULES([CPPUNIT], [cppunit >= 1.10.0], , AC_MSG_ERROR([CppUnit 1.10.0 or newer not found]))
else
	AC_MSG_RESULT(no)
fi
AM_CONDITIONAL([BUILD_TESTS], [test "x${build_tests}" = "xyes"])

# Build with support for parsing XML configuration files
AC_ARG_WITH(
	[xmlcfg],
	AC_HELP_STRING([--with-xmlcfg], [Build with support for IRMA/Idemix XML configuration files; requires libxml]),
	[build_xmlcfg="${withval}"],
	[build_xmlcfg="yes"]
)

AC_MSG_CHECKING(if building with XML configuration file support)
if test "x${build_xmlcfg}" = "xyes" ; then
	AC_MSG_RESULT(yes)
	PKG_CHECK_MODULES([XML], [libxml-2.0 >= 2.0], , AC_MSG_ERROR([libxml2 2.0 or newer not found]))
else
	AC_MSG_RESULT(no)
fi
AM_CONDITIONAL([BUILD_XMLCFG], [test "x${build_xmlcfg}" = "xyes"])

# Check for libraries
ACX_GMP

PKG_CHECK_MODULES([OPENSSL], [libcrypto >= 0.9.8], , AC_MSG_ERROR([OpenSSL cryptography library 0.9.8 or newer not found]))
AC_CHECK_LIB(crypto, BN_init)

#PKG_CHECK_MODULES([LIBCONFIG], [libconfig >= 1.3.2],, AC_MSG_ERROR([libconfig 1.3.2 or newer not found]))

# Check for headers
AC_HEADER_STDC

# Check for functions
AC_FUNC_MEMCMP

# Check for clock_gettime
AC_SEARCH_LIBS([clock_gettime],[rt posix4])

##
## Architecture/Platform specific fixes
##

# Add -lgdi32 when building for MinGW
case "${host}" in
	*-mingw*)
		LIBS="${LIBS} -lgdi32"
		LDFLAGS="${LDFLAGS} -static-libgcc"
		;;
esac

# Define default paths
full_sysconfdir=`eval eval eval eval eval echo "${sysconfdir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
full_localstatedir=`eval eval eval eval eval echo "${localstatedir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
full_libdir=`eval eval eval eval eval echo "${libdir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
default_silvia_conf="`eval echo ${full_sysconfdir} | sed s,NONE,$ac_default_prefix,g`/silvia.conf"
default_pid_file="`eval echo ${full_localstatedir} | sed s,NONE,$ac_default_prefix,g`/run/silvia.pid"

# Define some variables for the code
AC_DEFINE_UNQUOTED(
	[VERSION_MAJOR],
	[SILVIA_VERSION_MAJOR],
	[Major version number]
)
AC_DEFINE_UNQUOTED(
	[VERSION_MINOR],
	[SILVIA_VERSION_MINOR],
	[Minor version number]
)
AC_DEFINE_UNQUOTED(
	[SILVIA_LOGLEVEL],
	[$SILVIA_LOGLEVEL],
	[The log level set by the user]
)
AC_DEFINE_UNQUOTED(
	[DEFAULT_SILVIA_CONF],
	["$default_silvia_conf"],
	[The default configuration file]
)
AC_DEFINE_UNQUOTED(
	[DEFAULT_SILVIA_PIDFILE],
	["$default_pid_file"],
	[The default PID file]
)

# Generate theinstall script
AC_PROG_INSTALL

# Generate the makefiles
AC_CONFIG_FILES([
	Makefile
	silvia.pc
	src/Makefile
	src/bin/Makefile
	src/bin/keygen/Makefile
	src/bin/verifier/Makefile
	src/bin/loader/Makefile
	src/bin/issuer/Makefile
	src/lib/Makefile
	src/lib/test/Makefile
	src/lib/common/Makefile
	src/lib/common/test/Makefile
	src/lib/issuer/Makefile
	src/lib/issuer/test/Makefile
	src/lib/prover/Makefile
	src/lib/prover/test/Makefile
	src/lib/verifier/Makefile
	src/lib/verifier/test/Makefile
	src/lib/pcsc/Makefile
	src/lib/pcsc/test/Makefile
	src/lib/xml/Makefile
	src/lib/xml/test/Makefile
	src/lib/nfc/Makefile
	src/lib/nfc/test/Makefile
])

AC_OUTPUT
