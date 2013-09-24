/* $Id: silvia_prover.cpp 54 2013-07-04 12:04:51Z rijswijk $ */

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
#include "silvia_prover.h"
#include "silvia_rand.h"
#include "silvia_macros.h"
#include "silvia_hash.h"
#include "silvia_asn1.h"
#include <vector>
#include <assert.h>

silvia_prover::silvia_prover(silvia_pub_key* pubkey, silvia_credential* credential)
{
	this->pubkey = pubkey;
	this->credential = credential;
}
	
void silvia_prover::prove
(
	std::vector<bool> D,
	mpz_class n1,
	mpz_class context,
	mpz_class& c,
	mpz_class& A_prime,
	mpz_class& e_hat,
	mpz_class& v_prime_hat,
	std::vector<mpz_class>& a_i_hat,
	std::vector<silvia_attribute*>& a_i,
	mpz_class* ext_e_tilde /* = NULL */,
	mpz_class* ext_v_prime_tilde /* = NULL */,
	mpz_class* ext_r_A /* = NULL */,
	std::vector<mpz_class>* ext_a_tilde /* = NULL */
)
{
	size_t irma_kludge_dec_r_A 				= 0;
	size_t irma_kludge_dec_v_prime_tilde 	= 0;
	
	if (SYSPAR(irma_kludge_enabled))
	{
		size_t r_A_mul_e_bits = SYSPAR(l_n) + SYSPAR(l_statzk) + SYSPAR(l_e);
		
		if (r_A_mul_e_bits >= SYSPAR(l_v))
		{
			irma_kludge_dec_r_A = (r_A_mul_e_bits - SYSPAR(l_v)) + 1;
		}
		
		irma_kludge_dec_v_prime_tilde = 8;
	}
	
	// Generate random blinding values
	mpz_class e_tilde = (ext_e_tilde == NULL) ? silvia_rng::i()->get_random(SYSPAR(l_e_prime) + SYSPAR(l_statzk) + SYSPAR(l_H)) : *ext_e_tilde;
	mpz_class v_prime_tilde = (ext_v_prime_tilde == NULL) ? silvia_rng::i()->get_random(SYSPAR(l_v) + SYSPAR(l_statzk) + SYSPAR(l_H) - irma_kludge_dec_v_prime_tilde) : *ext_v_prime_tilde;
	mpz_class r_A = (ext_r_A == NULL) ? silvia_rng::i()->get_random(SYSPAR(l_n) + SYSPAR(l_statzk) - irma_kludge_dec_r_A) : *ext_r_A;
	
	std::vector<mpz_class> a_tilde;
	std::vector<size_t> R_index; // will hold references to the index in the R bases used in the ZKPs for unrevealed attributes
	R_index.push_back(0); // we always hide the master secret!
	
	if (ext_a_tilde == NULL)
	{
		// Add random blinding value for the master secret
		a_tilde.push_back(silvia_rng::i()->get_random(SYSPAR(l_m) + SYSPAR(l_statzk) + SYSPAR(l_H)));
		
		size_t r_index = 1;
		
		for (std::vector<bool>::iterator i = D.begin(); i != D.end(); i++)
		{
			if (*i == false)
			{
				// Add random blinding value for attribute that will not be revealed
				a_tilde.push_back(silvia_rng::i()->get_random(SYSPAR(l_m) + SYSPAR(l_statzk) + SYSPAR(l_H)));
				R_index.push_back(r_index);
			}
			
			r_index++;
		}
	}
	else
	{
		a_tilde = *ext_a_tilde;
		
		size_t r_index = 1;
		
		for (std::vector<bool>::iterator i = D.begin(); i != D.end(); i++)
		{
			if (*i == false)
			{
				R_index.push_back(r_index);
			}
			
			r_index++;
		}
	}
	
	// Calculate A'
	mpz_class S_r_A;
	mpz_powm(_Z(S_r_A), _Z(pubkey->get_S()), _Z(r_A), _Z(pubkey->get_n()));
	
	A_prime = credential->get_A() * S_r_A;
	
	mpz_mod(_Z(A_prime), _Z(A_prime), _Z(pubkey->get_n()));
	
	// Calculate Z~
	
	// Calculate factor A'^e~
	mpz_class A_prime_e_tilde;
	mpz_powm(_Z(A_prime_e_tilde), _Z(A_prime), _Z(e_tilde), _Z(pubkey->get_n()));
	
	// Calculate factor S^v'~
	mpz_class S_v_prime_tilde;
	mpz_powm(_Z(S_v_prime_tilde), _Z(pubkey->get_S()), _Z(v_prime_tilde), _Z(pubkey->get_n()));
	
	// Compute factors Ri^ai~ for non-disclosed attributes including the master secret
	mpz_class Ri_factor(1);
	
	std::vector<size_t>::iterator r_index = R_index.begin();
	
	for (std::vector<mpz_class>::iterator i = a_tilde.begin(); i != a_tilde.end(); i++)
	{
		// Compute Ri^ai~
		mpz_class Ri_ai_tilde;
		mpz_powm(_Z(Ri_ai_tilde), _Z(pubkey->get_R()[*r_index]), _Z((*i)), _Z(pubkey->get_n()));
		
		// Factor it in
		Ri_factor *= Ri_ai_tilde;
		mpz_mod(_Z(Ri_factor), _Z(Ri_factor), _Z(pubkey->get_n()));
		
		r_index++;
	}
	
	// Now assemble all the factors to compute Z~
	mpz_class Z_tilde = A_prime_e_tilde * S_v_prime_tilde * Ri_factor;
	mpz_mod(_Z(Z_tilde), _Z(Z_tilde), _Z(pubkey->get_n()));
	
	// Compute proof hash c
	
	// Create ASN.1 DER encoding of value to hash
	silvia_asn1_sequence challenge_seq;
	
	silvia_asn1_integer context_asn1(context);
	challenge_seq.append(&context_asn1);
	
	silvia_asn1_integer A_prime_asn1(A_prime);
	challenge_seq.append(&A_prime_asn1);
	
	silvia_asn1_integer Z_tilde_asn1(Z_tilde);
	challenge_seq.append(&Z_tilde_asn1);
	
	silvia_asn1_integer n1_asn1(n1);
	challenge_seq.append(&n1_asn1);
	
	// Hash the data
	silvia_hash h(SYSPAR(hash_type));
	
	h.init();
	h.update(challenge_seq.get_der_encoding());
	c = h.final();
	
	// Compute e'
	mpz_class e_prime = credential->get_e();
	mpz_clrbit(_Z(e_prime), SYSPAR(l_e) - 1);
	
	// Compute v'
	mpz_class v_prime = credential->get_v() - (credential->get_e() * r_A);
	mpz_class dec_factor = (credential->get_e() * r_A);
	
	// Compute e^
	e_hat = e_tilde + (c * e_prime);
	
	// Compute v'^
	v_prime_hat = v_prime_tilde + (c * v_prime);
	
	// Compute s^ and add it to the set of hidden attributes
	std::vector<mpz_class>::iterator a_tilde_it = a_tilde.begin();
	
	a_i_hat.push_back(*a_tilde_it + (c * credential->get_secret().rep()));
	a_tilde_it++;
	
	// Compute a_i^ for hidden attributes and reveal other attributes
	size_t a_index = 0;
	
	for (std::vector<bool>::iterator i = D.begin(); i != D.end(); i++)
	{
		if (*i == false)
		{
			a_i_hat.push_back(*a_tilde_it + (c * credential->get_attribute(a_index++)->rep()));
			a_tilde_it++;
		}
		else
		{
			a_i.push_back(credential->get_attribute(a_index++));
		}
	}
}
