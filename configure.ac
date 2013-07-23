dnl
dnl $Id: configure.ac 57 2013-07-04 18:07:24Z rijswijk $
dnl

################################################################################
# Version information                                                          #
################################################################################

# Program version

define([SILVIA_VERSION_MAJOR], [0])
define([SILVIA_VERSION_MINOR], [1])
define([SILVIA_VERSION_BUILDREV], esyscmd([sh -c "svnversion|tr -d '\n'"]))
define([PACKAGE_SUFFIX], [])

# Library version

# Code changed:                      SILVIA_VERSION_REVISION++
# Interface added/removed/changed:   SILVIA_VERSION_CURRENT++, SILVIA_VERSION_REVISION=0
# Interface added:                   SILVIA_VERSION_AGE++
# Interface removed:                 SILVIA_VERSION_AGE=0

define([SILVIA_VERSION_CURRENT], [0])
define([SILVIA_VERSION_AGE], [0])
define([SILVIA_VERSION_REVISION], [0])

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

# Log level
AC_ARG_WITH(
	[loglevel],
	[AS_HELP_STRING([--with-loglevel=INT],[The log level. 0=No log 1=Error 2=Warning 3=Info 4=Debug (default INT=3)])],
	[SILVIA_LOGLEVEL="$withval"],
	[SILVIA_LOGLEVEL=3]
)

# Check for libraries
ACX_OPENSSL(0,9,8)
ACX_GMP
AM_PATH_CPPUNIT(1.10.0, , AC_MSG_ERROR([libcppunit 1.10.0 or newer not found]))

PKG_CHECK_MODULES([LIBCRYPTO], [libcrypto >= 0.9.8], , AC_MSG_ERROR([OpenSSL cryptography library 0.9.8 or newer not found]))
AC_CHECK_LIB(crypto, BN_init)

PKG_CHECK_MODULES([PCSC], [libpcsclite >= 1.4.0], , AC_MSG_ERROR([PC/SC lite 1.4.0 or newer not found]))
AC_CHECK_LIB(pcsclite, SCardConnect)

PKG_CHECK_MODULES([CPPUNIT], [cppunit >= 1.10.0], , AC_MSG_ERROR([CppUnit 1.10.0 or newer not found]))

#PKG_CHECK_MODULES([LIBCONFIG], [libconfig >= 1.3.2],, AC_MSG_ERROR([libconfig 1.3.2 or newer not found]))

# Check for headers
AC_HEADER_STDC

# Check for functions
AC_FUNC_MEMCMP

# Check for clock_gettime
AC_SEARCH_LIBS([clock_gettime],[rt posix4])

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
	src/Makefile
	src/bin/Makefile
	src/bin/keygen/Makefile
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
])

AC_OUTPUT
