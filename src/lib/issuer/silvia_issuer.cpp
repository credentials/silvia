/* $Id: silvia_issuer.cpp 54 2013-07-04 12:04:51Z rijswijk $ */

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
#include "silvia_rand.h"
#include "silvia_issuer.h"
#include "silvia_types.h"
#include "silvia_parameters.h"
#include "silvia_macros.h"
#include "silvia_asn1.h"
#include "silvia_hash.h"

silvia_issuer::silvia_issuer(silvia_pub_key* pubkey, silvia_priv_key* privkey)
{
	this->pubkey = pubkey;
	this->privkey = privkey;
	
	issuer_state = ISSUER_START;
}
	
void silvia_issuer::set_attributes(const std::vector<silvia_attribute*> a)
{
	assert(issuer_state == ISSUER_START);
	
	this->a = a;
	
	issuer_state = ISSUER_ATTRIBUTES;
}

mpz_class silvia_issuer::get_issuer_nonce(mpz_class* ext_n1 /* = NULL*/)
{
	assert(issuer_state == ISSUER_ATTRIBUTES);
	
	if (ext_n1 == NULL)
	{
		// Generate new issuer nonce
		n1 = silvia_rng::i()->get_random(SYSPAR(l_statzk));
	}
	else
	{
		// Copy supplied nonce
		n1 = *ext_n1;
	}
	
	issuer_state = ISSUER_NONCE;
	
	return n1;
}
	
bool silvia_issuer::submit_and_verify_commitment(mpz_class context, mpz_class U, mpz_class c, mpz_class v_prime_hat, mpz_class s_hat)
{
	assert(issuer_state == ISSUER_NONCE);
	
	// Check length of v'^
	if (mpz_sizeinbase(_Z(v_prime_hat), 2) > SYSPAR(l_n) + SYSPAR(l_statzk)*2 + SYSPAR(l_H) + 1)
	{
		issuer_state = ISSUER_INVALID;
		
		return false;
	}
	
	// Negate c
	mpz_class c_neg = -c;
	
	// Compute U^
	
	// Compute factor U^-c
	mpz_class U_c_neg;
	mpz_powm(_Z(U_c_neg), _Z(U), _Z(c_neg), _Z(pubkey->get_n()));
	
	// Compute factor S^v'^
	mpz_class S_v_prime_hat;
	mpz_powm(_Z(S_v_prime_hat), _Z(pubkey->get_S()), _Z(v_prime_hat), _Z(pubkey->get_n()));
	
	// Compute factor R_0^s^
	mpz_class R0_s_hat;
	mpz_powm(_Z(R0_s_hat), _Z(pubkey->get_R()[0]), _Z(s_hat), _Z(pubkey->get_n()));
	
	// Now compose U^ from the factors
	mpz_class U_hat = U_c_neg * S_v_prime_hat * R0_s_hat;
	mpz_mod(_Z(U_hat), _Z(U_hat), _Z(pubkey->get_n()));
	
	// Create hash c^ from the data the issuer knows
	
	// Create ASN.1 encoding of all the data to hash
	silvia_asn1_sequence challenge_seq;
	
	silvia_asn1_integer context_asn1(context);
	challenge_seq.append(&context_asn1);
	
	silvia_asn1_integer U_asn1(U);
	challenge_seq.append(&U_asn1);
	
	silvia_asn1_integer U_hat_asn1(U_hat);
	challenge_seq.append(&U_hat_asn1);
	
	silvia_asn1_integer n1_asn1(n1);
	challenge_seq.append(&n1_asn1);
	
	// Hash the data
	silvia_hash h(SYSPAR(hash_type));
	
	h.init();
	h.update(challenge_seq.get_der_encoding());
	mpz_class c_hat = h.final();
	
	// Compare c to c^
	if (c != c_hat)
	{
		issuer_state = ISSUER_INVALID;
		
		return false;
	}
	
	// Save state
	this->U = U;
	
	issuer_state = ISSUER_COMMITMENT;
	
	return true;
}
	
void silvia_issuer::compute_signature(mpz_class& A, mpz_class& e, mpz_class& v_prime_prime, mpz_class* ext_e /* = NULL */, mpz_class* ext_v_tilde /* = NULL */)
{
	assert(issuer_state == ISSUER_COMMITMENT);
	
	if (ext_e == NULL)
	{
		// Generate a prime e in the interval [2^l_e-1, 2^l_e-1 + 2^l_e'-1]
		mpz_class lower_bound;
		mpz_setbit(_Z(lower_bound), SYSPAR(l_e) - 1);
	
		mpz_class upper_bound;
		mpz_setbit(_Z(upper_bound), SYSPAR(l_e_prime) - 1);
		upper_bound += lower_bound;
		
		e = 0;
		
		while ((e < lower_bound) || (e > upper_bound))
		{
			e = lower_bound;
			
			e += silvia_rng::i()->get_random(SYSPAR(l_e_prime) - 1);
			
			while ((e < upper_bound) && !mpz_probab_prime_p(_Z(e), SYSPAR(rabin_miller_its)))
			{
				mpz_nextprime(_Z(e), _Z(e));
			}
		}
	}
	else
	{
		// Use externally supplied value for e
		e = *ext_e;
	}
	
	mpz_class v_tilde;
	
	if (ext_v_tilde == NULL)
	{
		v_tilde = silvia_rng::i()->get_random(SYSPAR(l_v) - 1);
	}
	else
	{
		v_tilde = *ext_v_tilde;
	}
	
	// Compute 2^l_v-1
	mpz_class two_l_v_1;
	mpz_setbit(_Z(two_l_v_1), SYSPAR(l_v) - 1);
	
	// Compute v''
	v_prime_prime = two_l_v_1 + v_tilde;
	
	// Compute Q
	
	// Compute the denominator term of Q
	
	// Compute factor S^v''
	mpz_class S_v_prime_prime;
	mpz_powm(_Z(S_v_prime_prime), _Z(pubkey->get_S()), _Z(v_prime_prime), _Z(pubkey->get_n()));
	
	// Compute factors for all attributes
	mpz_class R_a(1);
	size_t R_index = 1;
	
	for (std::vector<silvia_attribute*>::iterator i = a.begin(); i != a.end(); i++)
	{
		// Compute R(i)^a(i)
		mpz_class R_a_i;
		mpz_powm(_Z(R_a_i), _Z(pubkey->get_R()[R_index++]), _Z((*i)->rep()), _Z(pubkey->get_n()));
		
		// Factor in R(i)^a(i)
		R_a *= R_a_i;
		
		// Normalize in Z(n)
		mpz_mod(_Z(R_a), _Z(R_a), _Z(pubkey->get_n()));
	}
	
	mpz_class Q_denom = U * S_v_prime_prime * R_a;
	
	// Compute Q = Z * Q_denom^-1
	mpz_class Q_denom_inv;
	mpz_invert(_Z(Q_denom_inv), _Z(Q_denom), _Z(pubkey->get_n()));
	
	mpz_class Q = pubkey->get_Z() * Q_denom_inv;
	mpz_mod(_Z(Q), _Z(Q), _Z(pubkey->get_n()));
	
	// Compute A = Q^(e^-1 mod p'q')
	mpz_class e_inv;
	mpz_invert(_Z(e_inv), _Z(e), _Z(privkey->get_n_prime()));
	
	mpz_powm(_Z(A), _Z(Q), _Z(e_inv), _Z(pubkey->get_n()));
	
	// Save state
	this->Q = Q;
	this->e = e;
	this->A = A;
	this->v_prime_prime = v_prime_prime;
	
	issuer_state = ISSUER_SIGNATURE;
}
	
void silvia_issuer::prove_signature(mpz_class n2, mpz_class context, mpz_class& c, mpz_class& e_hat, mpz_class* r_ext /* = NULL */)
{
	assert(issuer_state == ISSUER_SIGNATURE);
	
	mpz_class r;
	
	if (r_ext == NULL)
	{
		r = silvia_rng::i()->get_random(SYSPAR(l_n));
		
		mpz_mod(_Z(r), _Z(r), _Z(privkey->get_n_prime()));
	}
	else
	{
		r = *r_ext;
	}
	
	// Compute A~
	mpz_class A_tilde;
	mpz_powm(_Z(A_tilde), _Z(Q), _Z(r), _Z(pubkey->get_n()));
	
	// Compute c
	
	// Create ASN.1 encoding of all the data to hash
	silvia_asn1_sequence challenge_seq;
	
	silvia_asn1_integer context_asn1(context);
	challenge_seq.append(&context_asn1);
	
	silvia_asn1_integer Q_asn1(Q);
	challenge_seq.append(&Q_asn1);
	
	silvia_asn1_integer A_asn1(A);
	challenge_seq.append(&A_asn1);
	
	silvia_asn1_integer n2_asn1(n2);
	challenge_seq.append(&n2_asn1);
	
	silvia_asn1_integer A_tilde_asn1(A_tilde);
	challenge_seq.append(&A_tilde_asn1);
	
	// Hash the data
	silvia_hash h(SYSPAR(hash_type));
	
	h.init();
	h.update(challenge_seq.get_der_encoding());
	c = h.final();
	
	// Compute e_hat
	mpz_class e_inv;
	mpz_invert(_Z(e_inv), _Z(e), _Z(privkey->get_n_prime()));
	
	e_hat = r - (c * e_inv);
	
	// Reduce module p'q'
	mpz_mod(_Z(e_hat), _Z(e_hat), _Z(privkey->get_n_prime()));
}
