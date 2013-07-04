# $Id: acx_gmp.m4 57 2013-07-04 18:07:24Z rijswijk $

AC_DEFUN([ACX_GMP],[
	AC_CHECK_LIB(gmp, __gmpz_init, , 
		[AC_MSG_ERROR([GNU MP not found, see http://gmplib.org/])])
	
	AC_CHECK_HEADERS([gmp.h])
	AC_CHECK_HEADERS([gmpxx.h])
])
