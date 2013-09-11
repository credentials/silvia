/* $Id: silvia_prover_credgen.h 54 2013-07-04 12:04:51Z rijswijk $ */

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

#ifndef _SILVIA_PROVER_CREDGEN_H
#define _SILVIA_PROVER_CREDGEN_H

#include <gmpxx.h>
#include "silvia_types.h"
#include <vector>

/**
 * Credential generator
 */
class silvia_credential_generator
{
public:
	/**
	 * Constructor
	 * @param pubkey the issuer's public key
	 */
	silvia_credential_generator(silvia_pub_key* pubkey);

	/**
	 * Set the attributes
	 * @param a the attributes
	 */
	void set_attributes(const std::vector<silvia_attribute*> a);

	/**
	 * Set the secret
	 * @param s the secret
	 */
	void set_secret(const silvia_integer_attribute s);

	/**
	 * Generate a new secret
	 */
	void new_secret();

	/**
	 * Compute the commitment
	 * @param U will take the computed commitment as output
	 * @param v_prime will take the blinding value as output
	 * @param ext_v_prime external value for v' (for testing only)
	 */
	void compute_commitment(mpz_class& U, mpz_class& v_prime, mpz_class* ext_v_prime = NULL);

	/**
	 * Prove the commitment; generates a zero-knowledge proof that
	 * proves that the commitment was generated correctly.
	 * @param n1 the issuer nonce n1
	 * @param context the context input used in the hash for the proof
	 * @param c will take the proof hash as output
	 * @param v_prime_hat will take the ZKP blinding value as output
	 * @param s_hat will take the blinded secret value as output
	 * @param ext_s_tilde external value for s~ (for testing only)
	 * @param ext_v_prime_tilde external value for v'~ (for testing only)
	 */
	void prove_commitment(mpz_class n1, mpz_class context, mpz_class& c, mpz_class& v_prime_hat, mpz_class& s_hat, mpz_class* ext_s_tilde = NULL, mpz_class* ext_v_prime_tilde = NULL);

	/**
	 * Retrieve the prover's nonce n2
	 * @param ext_n2 external value for n2 (for testing only)
	 * @return the prover nonce n2
	 */
	mpz_class get_prover_nonce(mpz_class* ext_n2 = NULL);

	/**
	 * Verify the CL signature made by the issuer
	 * @param context the context input used in the hash for the proof
	 * @param A the signature's A value
	 * @param e the signature's prime value e
	 * @param c the signature ZKP hash
	 * @param e_hat the signature ZKP e^ value
	 * @return true if the signature is valid
	 */
	bool verify_signature(mpz_class context, mpz_class A, mpz_class e, mpz_class c, mpz_class e_hat);

	/**
	 * Compute the final credential
	 * @param A the signature's A value
	 * @param e the signature's prime value e
	 * @param v_prime_prime the signer blinding value v''
	 */
	void compute_credential(mpz_class A, mpz_class e, mpz_class v_prime_prime);

	/**
	 * Verify the final credential
	 * @return true if the credential is valid
	 */
	bool verify_credential();

	/**
	 * Retrieve the final credential
	 * @return the full credential
	 */
	silvia_credential* get_credential();

private:
	// The issuer public key
	silvia_pub_key* pubkey;

	// The secret
	silvia_integer_attribute s;

	// The attributes
	std::vector<silvia_attribute*> a;

	// Internal state
	enum
	{
		CREDGEN_START,
		CREDGEN_ATTRIBUTES,
		CREDGEN_SECRET,
		CREDGEN_ATTRIBUTES_AND_SECRET,
		CREDGEN_COMMITTED,
		CREDGEN_PROVED_COMMITMENT,
		CREDGEN_RELEASED_N2,
		CREDGEN_VERIFIED_SIG,
		CREDGEN_COMPUTED_CRED,
		CREDGEN_VERIFIED_CRED,
		CREDGEN_INVALID
	}
	credgen_state;

	// Various state variables
	mpz_class U;
	mpz_class n1;
	mpz_class n2;
	mpz_class v_prime;

	// The CL signature
	mpz_class A;
	mpz_class e;
	mpz_class v;
};

#endif // !_SILVIA_PROVER_CREDGEN_H

