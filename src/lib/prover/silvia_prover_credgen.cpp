/* $Id: silvia_prover_credgen.cpp 54 2013-07-04 12:04:51Z rijswijk $ */

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
 silvia_prover_credgen.h

 Credential generator
 *****************************************************************************/

#include "config.h"
#include <gmpxx.h>
#include "silvia_types.h"
#include "silvia_parameters.h"
#include "silvia_prover_credgen.h"
#include "silvia_rand.h"
#include "silvia_macros.h"
#include "silvia_hash.h"
#include "silvia_asn1.h"
#include <vector>
#include <assert.h>

silvia_credential_generator::silvia_credential_generator(silvia_pub_key* pubkey)
{
	this->pubkey = pubkey;
	this->credgen_state = CREDGEN_START;
}

void silvia_credential_generator::set_attributes(const std::vector<silvia_attribute*> a)
{
	assert((credgen_state == CREDGEN_START) || (credgen_state == CREDGEN_SECRET));

	this->a = a;

	credgen_state = (credgen_state == CREDGEN_START) ? CREDGEN_ATTRIBUTES : CREDGEN_ATTRIBUTES_AND_SECRET;
}

void silvia_credential_generator::set_secret(const silvia_integer_attribute s)
{
	assert((credgen_state == CREDGEN_START) || (credgen_state == CREDGEN_ATTRIBUTES));

	this->s = s;

	credgen_state = (credgen_state == CREDGEN_START) ? CREDGEN_SECRET : CREDGEN_ATTRIBUTES_AND_SECRET;
}

void silvia_credential_generator::new_secret()
{
	assert((credgen_state == CREDGEN_START) || (credgen_state == CREDGEN_ATTRIBUTES_AND_SECRET));
	
	mpz_class s_val = silvia_rng::i()->get_random(SYSPAR(l_m));

	s = s_val;

	credgen_state = (credgen_state == CREDGEN_START) ? CREDGEN_SECRET : CREDGEN_ATTRIBUTES_AND_SECRET;
}

void silvia_credential_generator::compute_commitment(mpz_class& U, mpz_class& v_prime, mpz_class* ext_v_prime /* = NULL*/)
{
	assert(credgen_state == CREDGEN_ATTRIBUTES_AND_SECRET);

	if (ext_v_prime == NULL)
	{
		// Generate v'
		v_prime = silvia_rng::i()->get_random(SYSPAR(l_n) + SYSPAR(l_statzk));
	}
	else
	{
		// Use externally provided value for v'
		v_prime = *ext_v_prime;
	}
	
	// Compute commitment U
	// Factor S^v'
	mpz_class S_v_prime;
	mpz_powm(_Z(S_v_prime), _Z(pubkey->get_S()), _Z(v_prime), _Z(pubkey->get_n()));
	
	// Factor R_0^s
	mpz_class R_0_s;
	mpz_powm(_Z(R_0_s), _Z(pubkey->get_R()[0]), _Z(s.rep()), _Z(pubkey->get_n()));
	
	// U
	U = S_v_prime * R_0_s;
	
	// U mod n
	mpz_mod(_Z(U), _Z(U), _Z(pubkey->get_n()))	;
	
	// Save state
	this->v_prime = v_prime;
	this->U = U;
	
	credgen_state = CREDGEN_COMMITTED;
}

void silvia_credential_generator::prove_commitment(mpz_class n1, mpz_class context, mpz_class& c, mpz_class& v_prime_hat, mpz_class& s_hat, mpz_class* ext_s_tilde /* = NULL */, mpz_class* ext_v_prime_tilde /* = NULL */)
{
	assert(credgen_state == CREDGEN_COMMITTED);
	
	// Save issuer nonce n1
	this->n1 = n1;
	mpz_class s_tilde;

	if (ext_s_tilde == NULL)
	{
		// Select blinding value for s
		s_tilde = silvia_rng::i()->get_random(SYSPAR(l_m) + SYSPAR(l_statzk) + SYSPAR(l_H) + 1);
	}
	else
	{
		// Use externally provided value for s~
		s_tilde = *ext_s_tilde;
	}
	
	mpz_class v_prime_tilde;
	
	if (ext_v_prime_tilde == NULL)
	{
		// Select blinding value for v'
		v_prime_tilde = silvia_rng::i()->get_random(SYSPAR(l_n) + 2*SYSPAR(l_statzk) + SYSPAR(l_H));
	}
	else
	{
		// Use externally provided value for v'~
		v_prime_tilde = *ext_v_prime_tilde;
	}
	
	// Compute U~
	mpz_class U_tilde;
	
	// Factor S^v_prime_tilde
	mpz_class S_v_prime_tilde;
	mpz_powm(_Z(S_v_prime_tilde), _Z(pubkey->get_S()), _Z(v_prime_tilde), _Z(pubkey->get_n()));
	
	// Factor R_0^s_tilde
	mpz_class R_0_s_tilde;
	mpz_powm(_Z(R_0_s_tilde), _Z(pubkey->get_R()[0]), _Z(s_tilde), _Z(pubkey->get_n()));
	
	// U~
	U_tilde = S_v_prime_tilde * R_0_s_tilde;
	
	// U~ mod n
	mpz_mod(_Z(U_tilde), _Z(U_tilde), _Z(pubkey->get_n()));
	
	// Compute c
	
	// Create ASN.1 DER encoding of value to hash
	silvia_asn1_sequence challenge_seq;
	
	silvia_asn1_integer context_asn1(context);
	challenge_seq.append(&context_asn1);
	
	silvia_asn1_integer U_asn1(U);
	challenge_seq.append(&U_asn1);
	
	silvia_asn1_integer U_tilde_asn1(U_tilde);
	challenge_seq.append(&U_tilde_asn1);
	
	silvia_asn1_integer n1_asn1(n1);
	challenge_seq.append(&n1_asn1);
	
	// Hash the data
	silvia_hash h(SYSPAR(hash_type));
	
	h.init();
	h.update(challenge_seq.get_der_encoding());
	c = h.final();
	
	// Compute s^
	mpz_mul(_Z(s_hat), _Z(c), _Z(s.rep()));
	s_hat += s_tilde;
	
	// Compute v'^
	mpz_mul(_Z(v_prime_hat), _Z(c), _Z(v_prime));
	v_prime_hat += v_prime_tilde;
	
	credgen_state = CREDGEN_PROVED_COMMITMENT;
}

mpz_class silvia_credential_generator::get_prover_nonce(mpz_class* ext_n2 /* = NULL */)
{
	assert(credgen_state == CREDGEN_PROVED_COMMITMENT);
	
	credgen_state = CREDGEN_RELEASED_N2;
	
	if (ext_n2 == NULL)
	{
		return (n2 = silvia_rng::i()->get_random(SYSPAR(l_statzk)));
	}
	else
	{
		return (n2 = *ext_n2);
	}
}

bool silvia_credential_generator::verify_signature(mpz_class context, mpz_class A, mpz_class e, mpz_class c, mpz_class e_hat)
{
	assert(credgen_state == CREDGEN_RELEASED_N2);
	
	// Compute Q = A^e mod n
	mpz_class Q;
	
	mpz_powm(_Z(Q), _Z(A), _Z(e), _Z(pubkey->get_n()));
	
	// Compute A^
	mpz_class A_hat;
	
	// Compute c + e^*e
	mpz_class A_hat_exp = e_hat * e;
	A_hat_exp += c;
	
	mpz_powm(_Z(A_hat), _Z(A), _Z(A_hat_exp), _Z(pubkey->get_n()));
	
	// Compute c'
	
	// Create ASN.1 sequence encoding of all data to hash
	silvia_asn1_sequence challenge_seq;
	
	silvia_asn1_integer context_asn1(context);
	challenge_seq.append(&context_asn1);
	
	silvia_asn1_integer Q_asn1(Q);
	challenge_seq.append(&Q_asn1);
	
	silvia_asn1_integer A_asn1(A);
	challenge_seq.append(&A_asn1);
	
	silvia_asn1_integer n2_asn1(n2);
	challenge_seq.append(&n2_asn1);
	
	silvia_asn1_integer A_hat_asn1(A_hat);
	challenge_seq.append(&A_hat_asn1);
	
	// Hash the data
	silvia_hash h(SYSPAR(hash_type));
	
	h.init();
	h.update(challenge_seq.get_der_encoding());
	mpz_class c_prime = h.final();
	
	credgen_state = CREDGEN_VERIFIED_SIG;
	
	return (c == c_prime);
}

void silvia_credential_generator::compute_credential(mpz_class A, mpz_class e, mpz_class v_prime_prime)
{
	assert(credgen_state == CREDGEN_VERIFIED_SIG);
	
	// Store A,e
	this->A = A;
	this->e = e;
	
	// Construct v
	v = v_prime + v_prime_prime;
	
	credgen_state = CREDGEN_COMPUTED_CRED;
}

bool silvia_credential_generator::verify_credential()
{
	// Re-compute Z for comparison
	mpz_class Z;
	
	// First, factor in A^e * S^v * R0^s
	mpz_class A_e;
	mpz_class S_v;
	mpz_class R0_s;
	
	mpz_powm(_Z(A_e), _Z(A), _Z(e), _Z(pubkey->get_n()));
	mpz_powm(_Z(S_v), _Z(pubkey->get_S()), _Z(v), _Z(pubkey->get_n()));
	mpz_powm(_Z(R0_s), _Z(pubkey->get_R()[0]), _Z(s.rep()), _Z(pubkey->get_n()));
	
	Z = A_e * S_v * R0_s;
	
	mpz_mod(_Z(Z), _Z(Z), _Z(pubkey->get_n()));
	
	// Now factor in all attribute factor exponentiations
	int r_index = 1;
	
	for (std::vector<silvia_attribute*>::iterator i = a.begin(); i != a.end(); i++)
	{
		mpz_class Ri_a;
		
		mpz_powm(_Z(Ri_a), _Z(pubkey->get_R()[r_index++]), _Z((*i)->rep()), _Z(pubkey->get_n()));
		
		Z = Z * Ri_a;
		
		mpz_mod(_Z(Z), _Z(Z), _Z(pubkey->get_n()));
	}
	
	if (Z == pubkey->get_Z())
	{
		credgen_state = CREDGEN_VERIFIED_CRED;
		
		return true;
	}
	else
	{
		credgen_state = CREDGEN_INVALID;
		
		return false;
	}
}

silvia_credential* silvia_credential_generator::get_credential()
{
	assert(credgen_state == CREDGEN_VERIFIED_CRED);
	
	return new silvia_credential(s, a, A, e, v);
}
