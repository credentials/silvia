/* $Id: silvia_verifier.cpp 55 2013-07-04 14:19:14Z rijswijk $ */

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
 silvia_prover.h

 Credential proof generator
 *****************************************************************************/

#include "config.h"
#include <gmpxx.h>
#include "silvia_types.h"
#include "silvia_parameters.h"
#include "silvia_verifier.h"
#include "silvia_rand.h"
#include "silvia_macros.h"
#include "silvia_hash.h"
#include "silvia_asn1.h"
#include <vector>
#include <assert.h>

silvia_verifier::silvia_verifier(silvia_pub_key* pubkey)
{
	this->pubkey = pubkey;
	
	verifier_state = VERIFIER_START;
}

mpz_class silvia_verifier::get_verifier_nonce(mpz_class* ext_n1 /* = NULL */)
{
	assert(verifier_state == VERIFIER_START);
	
	verifier_state = VERIFIER_NONCE;
	
	if (ext_n1 == NULL)
	{
		return (n1 = silvia_rng::i()->get_random(SYSPAR(l_statzk)));
	}
	else
	{
		return (n1 = *ext_n1);
	}
}

bool silvia_verifier::verify
(
	std::vector<bool> D,
	mpz_class context,
	mpz_class c,
	mpz_class A_prime,
	mpz_class e_hat,
	mpz_class v_prime_hat,
	std::vector<mpz_class> a_i_hat,
	std::vector<silvia_attribute*> a_i
)
{
	assert(verifier_state == VERIFIER_NONCE);
	
	verifier_state = VERIFIER_START;
	
	// Check size of a_i^ values
	for (std::vector<mpz_class>::iterator i = a_i_hat.begin(); i != a_i_hat.end(); i++)
	{
		if (mpz_sizeinbase(_Z((*i)), 2) > SYSPAR(l_m) + SYSPAR(l_statzk) + SYSPAR(l_H) + 1)
		{
			return false;
		}
	}
	
	// Check size of e^
	if (mpz_sizeinbase(_Z(e_hat), 2) > SYSPAR(l_e_prime) + SYSPAR(l_statzk) + SYSPAR(l_H) + 1)
		return false;
		
	// Compute Z^
	
	// Compute denominator prod(R^ai)*A'^2^l_e-1 for revealed attributes
	mpz_class Z_denom = 1;
	std::vector<silvia_attribute*>::iterator a_it = a_i.begin();
	size_t r_index = 1;
	
	for (std::vector<bool>::iterator i = D.begin(); i != D.end(); i++)
	{		
		if (*i == true)
		{
			if (a_it == a_i.end())
			{
				return false; // prevent crashing because of running out of attributes to verify
			}
			
			mpz_class Ri_ai;
			mpz_powm(_Z(Ri_ai), _Z(pubkey->get_R()[r_index]), _Z((*a_it)->rep()), _Z(pubkey->get_n()));
			
			// Factor it in
			Z_denom *= Ri_ai;
			
			// Reduce in Z(n)
			mpz_mod(_Z(Z_denom), _Z(Z_denom), _Z(pubkey->get_n()));
			
			a_it++;
		}
		
		r_index++;
	}
	
	// Factor in A'^2^l_e-1
	mpz_class A_prime_2;
	mpz_class two_l_e_1;
	mpz_setbit(_Z(two_l_e_1), SYSPAR(l_e) - 1);
	mpz_powm(_Z(A_prime_2), _Z(A_prime), _Z(two_l_e_1), _Z(pubkey->get_n()));
	
	Z_denom *= A_prime_2;
	
	// Reduce in Z(n) and invert
	mpz_mod(_Z(Z_denom), _Z(Z_denom), _Z(pubkey->get_n()));
	mpz_invert(_Z(Z_denom), _Z(Z_denom), _Z(pubkey->get_n()));
	
	// Compute this factor of Z^
	mpz_class Z_hat_fac1;
	mpz_class c_neg = -c;
	Z_hat_fac1 = Z_denom * pubkey->get_Z();
	
	mpz_powm(_Z(Z_hat_fac1), _Z(Z_hat_fac1), _Z(c_neg), _Z(pubkey->get_n()));
	
	// Compute A'^e^
	mpz_class A_prime_e_hat;
	mpz_powm(_Z(A_prime_e_hat), _Z(A_prime), _Z(e_hat), _Z(pubkey->get_n()));
	
	// Compute factor for the hidden attributes
	mpz_class Ri_ai_hat = 1;
	r_index = 0;
	
	std::vector<mpz_class>::iterator ai_hat_it = a_i_hat.begin();
	
	// Factor in a_i^ value for the master secret
	mpz_class R0_a0;
	mpz_powm(_Z(R0_a0), _Z(pubkey->get_R()[r_index++]), _Z((*ai_hat_it)), _Z(pubkey->get_n()));
	ai_hat_it++;
	
	Ri_ai_hat *= R0_a0;
	mpz_mod(_Z(Ri_ai_hat), _Z(Ri_ai_hat), _Z(pubkey->get_n()));
	
	for (std::vector<bool>::iterator i = D.begin(); i != D.end(); i++)
	{
		if (*i == false)
		{
			if (ai_hat_it == a_i_hat.end()) // prevent running out of a_i^ values
			{
				return false;
			}
			
			mpz_class Ri_ai;
			mpz_powm(_Z(Ri_ai), _Z(pubkey->get_R()[r_index]), _Z((*ai_hat_it)), _Z(pubkey->get_n()));
			
			// Factor in the value and reduce in Z(n)
			Ri_ai_hat *= Ri_ai;
			mpz_mod(_Z(Ri_ai_hat), _Z(Ri_ai_hat), _Z(pubkey->get_n()));
			
			ai_hat_it++;
		}
		
		r_index++;
	}
	
	// Finally, compute S^v'^
	mpz_class S_v_prime_hat;
	mpz_powm(_Z(S_v_prime_hat), _Z(pubkey->get_S()), _Z(v_prime_hat), _Z(pubkey->get_n()));
	
	// Compose all the factors to get Z^
	mpz_class Z_hat = Z_hat_fac1 * A_prime_e_hat * Ri_ai_hat * S_v_prime_hat;
	
	// Reduce in Z(n)
	mpz_mod(_Z(Z_hat), _Z(Z_hat), _Z(pubkey->get_n()));
	
	// Compute proof hash c^
	
	// Create ASN.1 DER encoding of value to hash
	silvia_asn1_sequence challenge_seq;
	
	silvia_asn1_integer context_asn1(context);
	challenge_seq.append(&context_asn1);
	
	silvia_asn1_integer A_prime_asn1(A_prime);
	challenge_seq.append(&A_prime_asn1);
	
	silvia_asn1_integer Z_hat_asn1(Z_hat);
	challenge_seq.append(&Z_hat_asn1);
	
	silvia_asn1_integer n1_asn1(n1);
	challenge_seq.append(&n1_asn1);
	
	// Hash the data
	silvia_hash h(SYSPAR(hash_type));
	
	h.init();
	h.update(challenge_seq.get_der_encoding());
	mpz_class c_hat = h.final();
	
	return (c == c_hat);
}

void silvia_verifier::reset()
{
	verifier_state = VERIFIER_START;
}
