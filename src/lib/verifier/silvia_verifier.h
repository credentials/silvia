/* $Id: silvia_verifier.h 55 2013-07-04 14:19:14Z rijswijk $ */

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
 silvia_verifier.h

 Credential proof verifier
 *****************************************************************************/

#ifndef _SILVIA_VERIFIER_H
#define _SILVIA_VERIFIER_H

#include <gmpxx.h>
#include "silvia_types.h"
#include <vector>

/**
 * Verifier class
 */
 
class silvia_verifier
{
public:
	/**
	 * Constructor
	 * @param pubkey the issuer public key
	 */
	silvia_verifier(silvia_pub_key* pubkey);
	
	/**
	 * Get the verifier nonce
	 * @param ext_n1 externally supplied value for n1 (for testing only)
	 * @return the verifier nonce n1
	 */
	mpz_class get_verifier_nonce(mpz_class* ext_n1 = NULL);
	
	/**
	 * Verify the supplied proof
	 * @param D which attributes to hide and which to reveal
	 * @param context the shared context
	 * @param c the proof hash c
	 * @param A_prime the proof A' value
	 * @param e_hat the proof e^ value
	 * @param v_prime_hat the proof v'^ value
	 * @param a_i_hat the proof's a_i^ values (hidden attribute ZKP values)
	 * @param a_i the proof's revealed attributes
	 * @return true if the proof is valid
	 */
	bool verify
	(
		std::vector<bool> D,
		mpz_class context,
		mpz_class c,
		mpz_class A_prime,
		mpz_class e_hat,
		mpz_class v_prime_hat,
		std::vector<mpz_class> a_i_hat,
		std::vector<silvia_attribute*> a_i
	);
	
	/**
	 * Reset the verifier
	 */
	void reset();

private:
	// State
	silvia_pub_key* pubkey;
	mpz_class n1;
	
	enum
	{
		VERIFIER_START,
		VERIFIER_NONCE
	}
	verifier_state;
};

#endif // !_SILVIA_VERIFIER_H

