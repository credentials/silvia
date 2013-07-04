/* $Id: hashtests.cpp 45 2013-06-20 19:29:22Z rijswijk $ */

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
 hashtests.cpp

 Tests the hash implementations
 *****************************************************************************/

#include <stdlib.h>
#include <cppunit/extensions/HelperMacros.h>
#include <string>
#include "hashtests.h"
#include "silvia_hash.h"

CPPUNIT_TEST_SUITE_REGISTRATION(hash_tests);

void hash_tests::setUp()
{
}

void hash_tests::tearDown()
{
}

void hash_tests::test_hashing()
{
	silvia_hash sha1("sha1");
	silvia_hash sha256("sha256");
	silvia_hash sha512("sha512");

	mpz_class ABCDE("0x4142434445");
	std::string test = "Silvia is a friend of IRMA";

	sha1.init();
	sha1.update((const unsigned char*) test.c_str(), test.size());
	sha1.update(ABCDE);
	mpz_class sha1result = sha1.final();

	CPPUNIT_ASSERT(sha1result == mpz_class("0xbf485995741a49187863b7229c6f0d961e89761c"));

	sha256.init();
	sha256.update((const unsigned char*) test.c_str(), test.size());
	sha256.update(ABCDE);
	mpz_class sha256result = sha256.final();

	CPPUNIT_ASSERT(sha256result == mpz_class("0x84d07815b7d8275ed4ea26e8ef1fb16987793d89a468ffa1bef3a8564e6d8a85"));

	sha512.init();
	sha512.update((const unsigned char*) test.c_str(), test.size());
	sha512.update(ABCDE);
	mpz_class sha512result = sha512.final();

	CPPUNIT_ASSERT(sha512result == mpz_class("0x0f8e2526d058028c500bb0b9516c0f95fb04818497199fff17be16732a1e3de78c2831a40ab14d91a1b11e018d71a4a1ded8cbbb12bc9ee319db163c485f8660"));
}

