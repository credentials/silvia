/* $Id: silvia_issuer.h 54 2013-07-04 12:04:51Z rijswijk $ */

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
 silvia_issuer.h

 Credential issuer
 *****************************************************************************/

#ifndef _SILVIA_ISSUER_H
#define _SILVIA_ISSUER_H

#include <gmpxx.h>
#include "silvia_types.h"

/**
 * Credential issuer class
 */
class silvia_issuer
{
public:
	/**
	 * Constructor
	 * @param pubkey the issuer public key
	 * @param privkey the issuer private key
	 */
	silvia_issuer(silvia_pub_key* pubkey, silvia_priv_key* privkey);
	
	/**
	 * Set the attributes
	 * @param a the attributes for the new credential
	 */
	void set_attributes(const std::vector<silvia_attribute*> a);
	
	/**
	 * Get the issuer nonce n1
	 * @param ext_n1 externally supplied value for n1 (for testing only)
	 * @return the issuer nonce n1
	 */
	mpz_class get_issuer_nonce(mpz_class* ext_n1 = NULL);
	
	/**
	 * Submit the commitment and verify the proof
	 * @param context the context data
	 * @param U the commitment U
	 * @param c the proof hash c
	 * @param v_prime_hat the proof blinding value v'^
	 * @param s_hat the blinded secret s
	 * @return true if the commitment was accepted and the proof verifies correctly
	 */
	bool submit_and_verify_commitment(mpz_class context, mpz_class U, mpz_class c, mpz_class v_prime_hat, mpz_class s_hat);
	
	/**
	 * Compute the CL signature on the credential
	 * @param A the output value A of the CL signature
	 * @param e the output value e (prime) of the CL signature
	 * @param v_prime_prime the output value v'' of the CL signature
	 * @param ext_e externally supplied value for e (for testing only)
	 * @param ext_v_tilde externally supplied value for v~ (for testing only)
	 */
	void compute_signature(mpz_class& A, mpz_class& e, mpz_class& v_prime_prime, mpz_class* ext_e = NULL, mpz_class* ext_v_tilde = NULL);
	
	/**
	 * Produce the proof of correctness for the signature
	 * @param n2 the prover nonce n2
	 * @param c the output hash c for the proof
	 * @param e_hat the output value e^ for the proof
	 * @param r_ext externally supplied value for r (for testing only)
	 */
	void prove_signature(mpz_class n2, mpz_class context, mpz_class& c, mpz_class& e_hat, mpz_class* r_ext = NULL);
	
	/**
	 * Reset the issuer state
	 */
	void reset();

private:
	// State
	std::vector<silvia_attribute*> a; 	// credential attributes
	mpz_class n1;						// issuer nonce
	mpz_class U;						// commitment
	mpz_class Q;						// signature base
	mpz_class A;						// signature value A
	mpz_class e;						// signature value e
	mpz_class v_prime_prime;			// signature value v''
	
	enum
	{
		ISSUER_START,
		ISSUER_ATTRIBUTES,
		ISSUER_NONCE,
		ISSUER_COMMITMENT,
		ISSUER_SIGNATURE,
		ISSUER_SIGNATURE_PROOF,
		ISSUER_INVALID
	}
	issuer_state;

	// Issuer keys
	silvia_pub_key* pubkey;
	silvia_priv_key* privkey;
};

#endif // !_SILVIA_ISSUER_H

