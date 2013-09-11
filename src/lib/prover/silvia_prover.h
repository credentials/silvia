/* $Id: silvia_prover.h 54 2013-07-04 12:04:51Z rijswijk $ */

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

#ifndef _SILVIA_PROVER_H
#define _SILVIA_PROVER_H

#include <gmpxx.h>
#include "silvia_types.h"
#include <vector>

/**
 * Prover class
 */
 
class silvia_prover
{
public:
	/**
	 * Constructor
	 * @param pubkey the issuer public key
	 * @param credential the credential
	 */
	silvia_prover(silvia_pub_key* pubkey, silvia_credential* credential);
	
	/**
	 * Construct a proof
	 * @param D the attributes to disclose; set an entry to true to disclose the corresponding attribute
	 * @param n1 the verifier nonce
	 * @param context the context value
	 * @param c the proof hash c output
	 * @param A_prime the proof's A' value output
	 * @param e_hat the proof's e^ value output
	 * @param v_prime_hat the proof's v'^ value output
	 * @param a_i_hat the proof's a_i^ value output
	 * @param a_i the proof's a_i value output
	 * @param ext_e_tilde externally supplied value for e~ (for testing only)
	 * @param ext_v_prime_tilde externally supplied value for v'~ (for testing only)
	 * @param ext_r_A externally supplied value for r_A (for testing only)
	 * @param ext_a_tilde externally supplied values for a~ (for testing only)
	 */
	void prove
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
		mpz_class* ext_e_tilde = NULL,
		mpz_class* ext_v_prime_tilde = NULL,
		mpz_class* ext_r_A = NULL,
		std::vector<mpz_class>* ext_a_tilde = NULL
	);

private:
	// State
	silvia_pub_key* pubkey;
	silvia_credential* credential;
};

#endif // !_SILVIA_PROVER_H

