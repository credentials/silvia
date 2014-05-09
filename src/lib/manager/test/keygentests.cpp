/* $Id: keygentests.cpp 52 2013-07-02 13:16:24Z rijswijk $ */

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
 keygentests.cpp

 Tests the key generation implementation
 *****************************************************************************/

#include <stdlib.h>
#include <cppunit/extensions/HelperMacros.h>
#include <string>
#include <gmpxx.h>
#include "keygentests.h"
#include "silvia_issuer_keygen.h"
#include <stdio.h>

CPPUNIT_TEST_SUITE_REGISTRATION(keygen_tests);

void keygen_tests::setUp()
{
}

void keygen_tests::tearDown()
{
}

void keygen_tests::test_keygen()
{
	return;
	silvia_pub_key* pub = NULL;
	silvia_priv_key* priv = NULL;

	printf("k"); fflush(stdout);

	// Generate a key-pair for 5 attributes
	silvia_issuer_keyfactory::i()->generate_keypair(5, &pub, &priv);

	printf("K"); fflush(stdout);

	// Check properties of the generated private key
	CPPUNIT_ASSERT(mpz_probab_prime_p(priv->get_p().get_mpz_t(), 40) >= 1);
	CPPUNIT_ASSERT(mpz_probab_prime_p(priv->get_q().get_mpz_t(), 40) >= 1);
	CPPUNIT_ASSERT(mpz_probab_prime_p(priv->get_p_prime().get_mpz_t(), 40) >= 1);
	CPPUNIT_ASSERT(mpz_probab_prime_p(priv->get_q_prime().get_mpz_t(), 40) >= 1);

	// Check properties of the generated public key
	CPPUNIT_ASSERT(pub->get_R().size() == 5);

	CPPUNIT_ASSERT(mpz_legendre(pub->get_S().get_mpz_t(), priv->get_p().get_mpz_t()) == 1);
	CPPUNIT_ASSERT(mpz_legendre(pub->get_S().get_mpz_t(), priv->get_q().get_mpz_t()) == 1);

	CPPUNIT_ASSERT(mpz_legendre(pub->get_Z().get_mpz_t(), priv->get_p().get_mpz_t()) == 1);
	CPPUNIT_ASSERT(mpz_legendre(pub->get_Z().get_mpz_t(), priv->get_q().get_mpz_t()) == 1);

	for (int i = 0; i < 5; i++)
	{
		CPPUNIT_ASSERT(mpz_legendre(pub->get_R()[i].get_mpz_t(), priv->get_p().get_mpz_t()) == 1);
		CPPUNIT_ASSERT(mpz_legendre(pub->get_R()[i].get_mpz_t(), priv->get_q().get_mpz_t()) == 1);
	}

	delete pub;
	delete priv;
}

