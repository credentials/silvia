/* $Id: issuetests.cpp 56 2013-07-04 17:39:15Z rijswijk $ */

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
 issuetests.cpp

 Perform an integral test of the full credential issuance protocol
 *****************************************************************************/

#include <stdlib.h>
#include <time.h>
#include <cppunit/extensions/HelperMacros.h>
#include <string>
#include <gmpxx.h>
#include "issuetests.h"
#include "silvia_issuer.h"
#include "silvia_issuer_keygen.h"
#include "silvia_prover_credgen.h"
#include "silvia_types.h"
#include "silvia_parameters.h"
#include "silvia_macros.h"
#include "silvia_rand.h"
#include "silvia_timer.h"

CPPUNIT_TEST_SUITE_REGISTRATION(issue_tests);

void issue_tests::setUp()
{
	// Ensure default parameters
	silvia_system_parameters::i()->reset();
}

void issue_tests::tearDown()
{
}

void issue_tests::test_issuance()
{
	////////////////////////////////////////////////////////////////////
	// Test context
	////////////////////////////////////////////////////////////////////
	
	mpz_class context = silvia_rng::i()->get_random(SYSPAR(l_H));
	
	////////////////////////////////////////////////////////////////////
	// Test attributes
	////////////////////////////////////////////////////////////////////
	
	silvia_string_attribute a1("Silvia IRMA's best friend");
	silvia_integer_attribute a2(50);
	silvia_boolean_attribute a3(true);
	
	std::vector<silvia_attribute*> attributes;
	
	attributes.push_back(&a1);
	attributes.push_back(&a2);
	attributes.push_back(&a3);
	
	////////////////////////////////////////////////////////////////////
	// Generate test key-pair
	////////////////////////////////////////////////////////////////////
	
	silvia_pub_key* pubkey;
	silvia_priv_key* privkey;
	
	printf("k"); fflush(stdout);
	
	silvia_issuer_keyfactory::i()->generate_keypair(3 + 1, &pubkey, &privkey);
	
	printf("K"); fflush(stdout);
	
	////////////////////////////////////////////////////////////////////
	// Run through the issuance protocol <cred_count> times
	////////////////////////////////////////////////////////////////////
	
	silvia_timer timer;
	
	int cred_count = 100;
	
	timer.mark();
	
	for (int i = 0; i < cred_count; i++)
	{
		if (i % 100 == 0)
		{
			printf("o");
			fflush(stdout);
		} 
		else if (i % 10 == 0)
		{
			printf(".");
			fflush(stdout);
		}
		
		silvia_issuer issuer(pubkey, privkey);
	
		silvia_credential_generator credgen(pubkey);
		
		////////////////////////////////////////////////////////////////
		// Step 1 (PROVER): new prover secret
		////////////////////////////////////////////////////////////////
		
		credgen.new_secret();
		credgen.set_attributes(attributes);
		
		////////////////////////////////////////////////////////////////
		// Step 2 (PROVER): compute prover commitment
		////////////////////////////////////////////////////////////////
		
		mpz_class U;
		mpz_class v_prime;
		
		credgen.compute_commitment(U, v_prime);
		
		////////////////////////////////////////////////////////////////
		// Step 3 (ISSUER): get issuer nonce n1
		////////////////////////////////////////////////////////////////
		
		issuer.set_attributes(attributes);
		
		mpz_class n1 = issuer.get_issuer_nonce();
		
		////////////////////////////////////////////////////////////////
		// Step 4 (PROVER): prove commitment
		////////////////////////////////////////////////////////////////
		
		mpz_class c_commit;
		mpz_class v_prime_hat;
		mpz_class s_hat;
		
		credgen.prove_commitment(n1, context, c_commit, v_prime_hat, s_hat);
		
		////////////////////////////////////////////////////////////////
		// Step 5 (ISSUER): verify the proof on the commitment
		////////////////////////////////////////////////////////////////
		
		CPPUNIT_ASSERT(issuer.submit_and_verify_commitment(context, U, c_commit, v_prime_hat, s_hat) == true);
		
		////////////////////////////////////////////////////////////////
		// Step 6 (ISSUER): compute signature
		////////////////////////////////////////////////////////////////
		
		mpz_class A;
		mpz_class e;
		mpz_class v_prime_prime;
		
		issuer.compute_signature(A, e, v_prime_prime);
		
		////////////////////////////////////////////////////////////////
		// Step 7 (PROVER): get prover nonce n2
		////////////////////////////////////////////////////////////////
		
		mpz_class n2 = credgen.get_prover_nonce();
		
		////////////////////////////////////////////////////////////////
		// Step 8 (ISSUER): compute signature proof
		////////////////////////////////////////////////////////////////
		
		mpz_class c_signature;
		mpz_class e_hat;
		
		issuer.prove_signature(n2, context, c_signature, e_hat);
		
		////////////////////////////////////////////////////////////////
		// Step 9 (PROVER): verify signature proof
		////////////////////////////////////////////////////////////////
		
		CPPUNIT_ASSERT(credgen.verify_signature(context, A, e, c_signature, e_hat) == true);
		
		////////////////////////////////////////////////////////////////
		// Step 10 (PROVER): compute credential
		////////////////////////////////////////////////////////////////
		
		credgen.compute_credential(A, e, v_prime_prime);
		
		////////////////////////////////////////////////////////////////
		// Step 11 (PROVER): verify credential
		////////////////////////////////////////////////////////////////
		
		CPPUNIT_ASSERT(credgen.verify_credential() == true);
	}
	
	////////////////////////////////////////////////////////////////////
	// Compute and output performance
	////////////////////////////////////////////////////////////////////
	
	unsigned long long elapsed = timer.elapsed();
	
	unsigned long long per_cred = elapsed / (1000*1000) / cred_count;
	
	printf("\n\nAverage time per credential for issuing: %llums\n\n", per_cred);
	
	////////////////////////////////////////////////////////////////////
	// Clean up
	////////////////////////////////////////////////////////////////////
	
	delete pubkey;
	delete privkey;
}
