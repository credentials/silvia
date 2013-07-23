/* $Id: silvia_macros.h 50 2013-06-30 11:28:35Z rijswijk $ */

/*
 * Copyright (c) 2013 Roland van Rijswijk-Deij
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 silvia_macros.h

 Utility macros
 *****************************************************************************/

#ifndef _SILVIA_MACROS_H
#define _SILVIA_MACROS_H

#include "config.h"
#include <string.h>

/**
 * _Z macro; used for mpz_ function parameters
 * @param var mpz_class-type variable to use as input for an mpz_ function
 */
#define _Z(var) var.get_mpz_t()

/**
 * printmpz; used to print mpz_class values as hex
 * @param mpz_val the value to print the hex representation for
 */
#define printmpz(mpz_val) { char* mpzstr = mpz_get_str(NULL, 16, mpz_val.get_mpz_t()); printf("%s (%zd)", mpzstr, mpz_sizeinbase(mpz_val.get_mpz_t(), 2)); free(mpzstr); }

/**
 * fprintmpz; used to print mpz_class values as hex to a file
 * @param f the file to write to
 * @param mpz_val the value to print the hex representation for
 */
#define fprintmpz(f, mpz_val) { char* mpzstr = mpz_get_str(NULL, 16, mpz_val.get_mpz_t()); fprintf(f, "%s", mpzstr, mpz_sizeinbase(mpz_val.get_mpz_t(), 2)); free(mpzstr); }

/**
 * fprintmpzdec; used to print mpz_class values as decimal to a file
 * @param f the file to write to
 * @param mpz_val the value to print the hex representation for
 */
#define fprintmpzdec(f, mpz_val) { char* mpzstr = mpz_get_str(NULL, 10, mpz_val.get_mpz_t()); fprintf(f, "%s", mpzstr, mpz_sizeinbase(mpz_val.get_mpz_t(), 2)); free(mpzstr); }

/**
 * FLAG_SET; returns true if a bit flag is set
 * @param flags flags field to test
 * @param flag flag to test
 */
#define FLAG_SET(flags, flag) ((flags & flag) == flag)

#endif // !_SILVIA_MACROS_H

