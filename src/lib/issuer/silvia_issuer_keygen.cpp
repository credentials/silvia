/* $Id: silvia_issuer_keygen.cpp 52 2013-07-02 13:16:24Z rijswijk $ */

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
 silvia_issuer_keygen.h

 Issuer key generation
 *****************************************************************************/

#include "config.h"
#include <vector>
#include <gmpxx.h>
#include <assert.h>
#include <openssl/bn.h>
#include "silvia_rand.h"
#include "silvia_issuer_keygen.h"
#include "silvia_types.h"
#include "silvia_parameters.h"
#include "silvia_macros.h"

////////////////////////////////////////////////////////////////////////////////
// Key factory
////////////////////////////////////////////////////////////////////////////////

// Initialise the one-and-only instance
/*static*/ std::auto_ptr<silvia_issuer_keyfactory> silvia_issuer_keyfactory::_i(NULL);

/*static*/ silvia_issuer_keyfactory* silvia_issuer_keyfactory::i()
{
	if (_i.get() == NULL)
	{
		_i = std::auto_ptr<silvia_issuer_keyfactory>(new silvia_issuer_keyfactory());
	}

	return _i.get();
}

silvia_issuer_keyfactory::silvia_issuer_keyfactory()
{
}

void silvia_issuer_keyfactory::generate_keypair
(
	size_t max_attr,
	silvia_pub_key** pubkey,
	silvia_priv_key** privkey
)
{
	assert(SYSPAR(l_n) % 2 == 0);	// p,q have half the size of n
	assert(SYSPAR(l_n) % 4 == 0);	// p',q' have half the size of p,q
	assert(SYSPAR(l_n) % 16 == 0);	// p, q must be a multiple of 8 bits

	assert(pubkey != NULL);
	assert(privkey != NULL);

	// Public key values
	std::vector<mpz_class> R;
	mpz_class S;
	mpz_class Z;
	mpz_class n;

	// Private key values
	mpz_class p;
	mpz_class q;

	// Compute prime size
	size_t prime_size = SYSPAR(l_n) / 2;

	// Generate p and q using OpenSSL safe prime generation
	BIGNUM* p_ossl = NULL;
	BIGNUM* q_ossl = NULL;
	
	do
	{
		p_ossl = BN_generate_prime(NULL, prime_size, 1 /* safe_prime */, NULL, NULL, NULL, NULL);
	}
	while (!BN_is_prime(p_ossl, SYSPAR(rabin_miller_its), NULL, NULL, NULL));
	
	do
	{
		q_ossl = BN_generate_prime(NULL, prime_size, 1 /* safe_prime */, NULL, NULL, NULL, NULL);
	}
	while (!BN_is_prime(q_ossl, SYSPAR(rabin_miller_its), NULL, NULL, NULL));

	// Convert OpenSSL values to big-endian large integers
	std::vector<unsigned char> p_val;
	std::vector<unsigned char> q_val;

	int p_size = BN_num_bytes(p_ossl);
	int q_size = BN_num_bytes(q_ossl);

	p_val.resize(p_size);
	q_val.resize(q_size);

	BN_bn2bin(p_ossl, &p_val[0]);
	BN_bn2bin(q_ossl, &q_val[0]);

	// FIXME: should be BN_clear_free if we want more security
	BN_free(p_ossl);
	BN_free(q_ossl);

	// Convert big-endian values from OpenSSL to GMP format
	mpz_import(_Z(p), p_size, 1, sizeof(unsigned char), 1, 0, &p_val[0]);
	mpz_import(_Z(q), q_size, 1, sizeof(unsigned char), 1, 0, &q_val[0]);

	// Compute p', q'
	mpz_class p_prime = p;
	p_prime -= 1;
	mpz_divexact_ui(_Z(p_prime), _Z(p_prime), 2);

	mpz_class q_prime = q;
	q_prime -= 1;
	mpz_divexact_ui(_Z(q_prime), _Z(q_prime), 2);

	// Compute n, n'
	n = p * q;
	mpz_class n_prime = p_prime * q_prime;

	// Find an acceptable value for S; we do this by picking a random
	// <SYSPAR(l_n)> value and checking whether it is a quadratic residue modulo n
	while (true)
	{
		S = silvia_rng::i()->get_random(SYSPAR(l_n));

		// Check if S \elem Z_n
		if (S > n) continue;

		// Check if S \elem QR_p and S \elem QR_q (implies: S \elem QR_n)
		if ((mpz_legendre(_Z(S), _Z(p)) == 1) &&
		    (mpz_legendre(_Z(S), _Z(q)) == 1))
		{
			break;
		}
	}

	// Derive Z from S
	mpz_class x;

	while (true)
	{
		x = silvia_rng::i()->get_random(prime_size);

		if ((x > 2) && (x < n_prime))
		{
			break;
		}
	}

	// Compute Z = S^x mod n
	mpz_powm(_Z(Z), _Z(S), _Z(x), _Z(n));

	// Derive R_i for i = 0..max_attr from S
	for (size_t i = 0; i < max_attr; i++)
	{
		mpz_class R_i;

		while (true)
		{
			x = silvia_rng::i()->get_random(prime_size);

			if ((x > 2) && (x < n_prime))
			{
				break;
			}
		}

		mpz_powm(_Z(R_i), _Z(S), _Z(x), _Z(n));

		R.push_back(R_i);
	}

	// Construct the return key-pair
	*pubkey = new silvia_pub_key(n, S, Z, R);
	*privkey = new silvia_priv_key(p, q);
}

