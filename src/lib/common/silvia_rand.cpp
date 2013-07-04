/* $Id: silvia_rand.cpp 50 2013-06-30 11:28:35Z rijswijk $ */

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
 silvia_rand.h

 System parameters
 *****************************************************************************/

#include "config.h"
#include "silvia_rand.h"
#include <vector>
#include <openssl/rand.h>
#include "silvia_macros.h"

// The one-and-only instance
/*static*/ std::auto_ptr<silvia_rng> silvia_rng::_i(NULL);

/*static*/ silvia_rng* silvia_rng::i()
{
	if (_i.get() == NULL)
	{
		_i = std::auto_ptr<silvia_rng>(new silvia_rng());
	}

	return _i.get();
}

silvia_rng::silvia_rng()
{
	// FIXME: init OpenSSL?
}

mpz_class silvia_rng::get_random(size_t n)
{
	// If n is a multiple of 8, use the simple way
	if (n % 8 == 0)
	{
		std::vector<unsigned char> rand_val;
		rand_val.resize(n/8);

		// FIXME: we should really check the return value of
		//        RAND_bytes as failure indicates a lack of proper
		//        entropy
		RAND_bytes(&rand_val[0], n / 8);

		// Now convert it to MPZ
		mpz_class rand;

		mpz_import(_Z(rand), n / 8, 1, sizeof(unsigned char), 0, 0, &rand_val[0]);

		return rand;
	}
	else
	{
		size_t num_bytes = (n / 8) + 1;

		// Compute the mask
		size_t mask_bits = n % 8;
		unsigned char mask = 0;

		while (mask_bits--)
		{
			mask = mask << 1;
			mask = mask + 0x01;
		}

		std::vector<unsigned char> rand_val;
		rand_val.resize(num_bytes);

		// FIXME: we should really check the return value of
		//        RAND_bytes as failure indicates a lack of proper
		//        entropy
		RAND_bytes(&rand_val[0], num_bytes);

		rand_val[0] &= mask;

		// Now convert it to MPZ
		mpz_class rand;

		mpz_import(_Z(rand), num_bytes, 1, sizeof(unsigned char), 0, 0, &rand_val[0]);

		return rand;
	}
}

