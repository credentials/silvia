/* $Id: proveverifytests.cpp 56 2013-07-04 17:39:15Z rijswijk $ */

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
 proveverifytests.cpp

 Perform an integral test of proving and verification
 *****************************************************************************/

#include <stdlib.h>
#include <time.h>
#include <cppunit/extensions/HelperMacros.h>
#include <string>
#include <gmpxx.h>
#include "proveverifytests.h"
#include "silvia_issuer.h"
#include "silvia_issuer_keygen.h"
#include "silvia_prover_credgen.h"
#include "silvia_prover.h"
#include "silvia_verifier.h"
#include "silvia_types.h"
#include "silvia_parameters.h"
#include "silvia_macros.h"
#include "silvia_rand.h"
#include "silvia_timer.h"

CPPUNIT_TEST_SUITE_REGISTRATION(proveverify_tests);

void proveverify_tests::setUp()
{
	// Ensure default parameters
	silvia_system_parameters::i()->reset();
}

void proveverify_tests::tearDown()
{
}

void proveverify_tests::test_prove_and_verify()
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
	// Issue test credential
	////////////////////////////////////////////////////////////////////
	
	printf("c"); fflush(stdout);
	
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
	
	mpz_class n1_iss = issuer.get_issuer_nonce();
	
	////////////////////////////////////////////////////////////////
	// Step 4 (PROVER): prove commitment
	////////////////////////////////////////////////////////////////
	
	mpz_class c_commit;
	mpz_class v_prime_hat_iss;
	mpz_class s_hat;
	
	credgen.prove_commitment(n1_iss, context, c_commit, v_prime_hat_iss, s_hat);
	
	////////////////////////////////////////////////////////////////
	// Step 5 (ISSUER): verify the proof on the commitment
	////////////////////////////////////////////////////////////////
	
	CPPUNIT_ASSERT(issuer.submit_and_verify_commitment(context, U, c_commit, v_prime_hat_iss, s_hat) == true);
	
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
	mpz_class e_hat_iss;
	
	issuer.prove_signature(n2, context, c_signature, e_hat_iss);
	
	////////////////////////////////////////////////////////////////
	// Step 9 (PROVER): verify signature proof
	////////////////////////////////////////////////////////////////
	
	CPPUNIT_ASSERT(credgen.verify_signature(context, A, e, c_signature, e_hat_iss) == true);
	
	////////////////////////////////////////////////////////////////
	// Step 10 (PROVER): compute credential
	////////////////////////////////////////////////////////////////
	
	credgen.compute_credential(A, e, v_prime_prime);
	
	////////////////////////////////////////////////////////////////
	// Step 11 (PROVER): verify credential
	////////////////////////////////////////////////////////////////
	
	CPPUNIT_ASSERT(credgen.verify_credential() == true);
	
	////////////////////////////////////////////////////////////////
	// Step 12 (PROVER): get credential
	////////////////////////////////////////////////////////////////
	
	silvia_credential* credential = credgen.get_credential();
	
	printf("C"); fflush(stdout);
	
	////////////////////////////////////////////////////////////////////
	// Parameter that determines the number of tests to run
	////////////////////////////////////////////////////////////////////
	
	size_t proof_count = 100;
	
	////////////////////////////////////////////////////////////////////
	// Now generate <proof_count> proofs for four different scenarios:
	//
	// - Disclosing all attributes
	// - Disclosing 2 attributes and hiding 1
	// - Disclosing 1 attribute and hiding 2
	// - Disclosing no attributes
	////////////////////////////////////////////////////////////////////
	
	silvia_prover prover(pubkey, credential);
	
	std::vector<mpz_class> c[4];
	std::vector<mpz_class> A_prime[4];
	std::vector<mpz_class> e_hat[4];
	std::vector<mpz_class> v_prime_hat[4];
	std::vector<std::vector<mpz_class> > a_i_hat[4];
	std::vector<std::vector<silvia_attribute*> > a_i[4];
	std::vector<mpz_class> n1[4];
	silvia_timer proof_timer;
	
	for (int scenario = 0; scenario < 4; scenario++)
	{
		c[scenario].resize(proof_count);
		A_prime[scenario].resize(proof_count);
		e_hat[scenario].resize(proof_count);
		v_prime_hat[scenario].resize(proof_count);
		a_i_hat[scenario].resize(proof_count);
		a_i[scenario].resize(proof_count);
		n1[scenario].resize(proof_count);
		
		// Construct set of attributes to disclose
		std::vector<bool> D;
		
		for (int i = 0; i < scenario; i++)
		{
			D.push_back(false);
		}
		
		for (int i = 1; i < (4 - scenario); i++)
		{
			D.push_back(true);
		}
		
		// Mark start time
		proof_timer.mark();
		
		for (int i = 0; i < proof_count ; i++)
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
			
			// Get a nonce
			n1[scenario][i] = silvia_rng::i()->get_random(SYSPAR(l_statzk));
			
			// Create the proof
			prover.prove(D, n1[scenario][i], context, c[scenario][i], A_prime[scenario][i], e_hat[scenario][i], v_prime_hat[scenario][i], a_i_hat[scenario][i], a_i[scenario][i]);
		}
		
		// Determine elapsed time
		unsigned long long elapsed = proof_timer.elapsed();
		
		printf("\n\nScenario %d: average time per proof is %llums\n\n", scenario, elapsed / (1000*1000) / proof_count);
	}
	
	////////////////////////////////////////////////////////////////////
	// Now verify the <proof_count> proofs for four different scenarios:
	//
	// - Disclosing all attributes
	// - Disclosing 2 attributes and hiding 1
	// - Disclosing 1 attribute and hiding 2
	// - Disclosing no attributes
	////////////////////////////////////////////////////////////////////
	
	silvia_verifier verifier(pubkey);
	
	silvia_timer verify_timer;
	
	for (int scenario = 0; scenario < 4; scenario++)
	{
		// Construct set of attributes to disclose
		std::vector<bool> D;
		
		for (int i = 0; i < scenario; i++)
		{
			D.push_back(false);
		}
		
		for (int i = 1; i < (4 - scenario); i++)
		{
			D.push_back(true);
		}
		
		// Mark start time
		verify_timer.mark();
		
		for (int i = 0; i < proof_count ; i++)
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
			
			// Verify the proof
			verifier.get_verifier_nonce(&n1[scenario][i]);
			CPPUNIT_ASSERT(verifier.verify(D, context, c[scenario][i], A_prime[scenario][i], e_hat[scenario][i], v_prime_hat[scenario][i], a_i_hat[scenario][i], a_i[scenario][i]) == true);
		}
		
		// Determine elapsed time
		unsigned long long elapsed = verify_timer.elapsed();
		
		printf("\n\nScenario %d: average time per verification is %llums\n\n", scenario, elapsed / (1000*1000) / proof_count);
	}
	
	////////////////////////////////////////////////////////////////////
	// Clean up
	////////////////////////////////////////////////////////////////////	
	
	delete credential;
	delete pubkey;
	delete privkey;
}
