/* $Id: typetests.cpp 47 2013-06-25 07:57:17Z rijswijk $ */

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
 typetests.cpp

 Tests the common type implementations
 *****************************************************************************/

#include <stdlib.h>
#include <cppunit/extensions/HelperMacros.h>
#include "typetests.h"
#include "silvia_types.h"
#include "silvia_macros.h"

CPPUNIT_TEST_SUITE_REGISTRATION(type_tests);

void type_tests::setUp()
{
}

void type_tests::tearDown()
{
}

void type_tests::test_silvia_pub_key()
{
	std::vector<mpz_class> R_test_1;

	R_test_1.push_back(4);

	silvia_pub_key test_pub1(1, 2, 3, R_test_1);

	CPPUNIT_ASSERT(test_pub1.get_n() == 1);
	CPPUNIT_ASSERT(test_pub1.get_S() == 2);
	CPPUNIT_ASSERT(test_pub1.get_Z() == 3);
	CPPUNIT_ASSERT(test_pub1.get_R().size() == 1);
	CPPUNIT_ASSERT(test_pub1.get_R()[0] == 4);

	silvia_pub_key test_pub2(mpz_class("0xA"), mpz_class("0xB"), mpz_class("0xC"), R_test_1);

	CPPUNIT_ASSERT(test_pub2.get_n() == 0xa);
	CPPUNIT_ASSERT(test_pub2.get_S() == 0xb);
	CPPUNIT_ASSERT(test_pub2.get_Z() == 0xc);
	CPPUNIT_ASSERT(test_pub2.get_R().size() == 1);
	CPPUNIT_ASSERT(test_pub2.get_R()[0] == 4);
}

void type_tests::test_silvia_priv_key()
{
	silvia_priv_key test_priv1(7, 11);

	CPPUNIT_ASSERT(test_priv1.get_p() == 7);
	CPPUNIT_ASSERT(test_priv1.get_q() == 11);
	CPPUNIT_ASSERT(test_priv1.get_p_prime() == 3);
	CPPUNIT_ASSERT(test_priv1.get_q_prime() == 5);

	silvia_priv_key test_priv2
	(
		mpz_class("0xfa2087628d1df70221cbd3deac8392633514db651f7f9c514f9e77109c9d54d39d3b6376260e08925fbd425d9eaba93c46e5857b0985036291746e9b8a5311f4f1ddc32fc4f2e03f6c0826f73e43ab0c6a8babd86780d18a1117ab5e4669b570653106a4d1a1dd915ff94bc09bbae85595afd069ef302e92249b399834a38ab3"),
		mpz_class("0xeff5aca4ea5022c502ea4015091c42b052ee758bfe82606472d8e08ebbbbfaada52950330e46c10968c236a8572c503f8b1f8f18b50ddc0a60dd9b789980acf37fb4540b7e3a916f87804e35333ef1bcd3ca087e2e6714276caf6d1ec0ce0917e67d53d78638de7c0e319d86b18a7d915744f537ff16fe15babc64d8bce5eb47")
	);

	CPPUNIT_ASSERT(test_priv2.get_p() == mpz_class("0xfa2087628d1df70221cbd3deac8392633514db651f7f9c514f9e77109c9d54d39d3b6376260e08925fbd425d9eaba93c46e5857b0985036291746e9b8a5311f4f1ddc32fc4f2e03f6c0826f73e43ab0c6a8babd86780d18a1117ab5e4669b570653106a4d1a1dd915ff94bc09bbae85595afd069ef302e92249b399834a38ab3"));
	CPPUNIT_ASSERT(test_priv2.get_q() == mpz_class("0xeff5aca4ea5022c502ea4015091c42b052ee758bfe82606472d8e08ebbbbfaada52950330e46c10968c236a8572c503f8b1f8f18b50ddc0a60dd9b789980acf37fb4540b7e3a916f87804e35333ef1bcd3ca087e2e6714276caf6d1ec0ce0917e67d53d78638de7c0e319d86b18a7d915744f537ff16fe15babc64d8bce5eb47"));
	CPPUNIT_ASSERT(test_priv2.get_p_prime() == mpz_class("0x7d1043b1468efb8110e5e9ef5641c9319a8a6db28fbfce28a7cf3b884e4eaa69ce9db1bb130704492fdea12ecf55d49e2372c2bd84c281b148ba374dc52988fa78eee197e279701fb604137b9f21d5863545d5ec33c068c5088bd5af2334dab83298835268d0eec8affca5e04ddd742acad7e834f7981749124d9ccc1a51c559"));
	CPPUNIT_ASSERT(test_priv2.get_q_prime() == mpz_class("0x77fad652752811628175200a848e215829773ac5ff413032396c70475dddfd56d294a81987236084b4611b542b96281fc58fc78c5a86ee05306ecdbc4cc05679bfda2a05bf1d48b7c3c0271a999f78de69e5043f17338a13b657b68f6067048bf33ea9ebc31c6f3e0718cec358c53ec8aba27a9bff8b7f0add5e326c5e72f5a3"));
}

void type_tests::test_attributes()
{
	silvia_attribute* generic = NULL;

	silvia_string_attribute s("Silvia is a good friend of IRMA");
	
	CPPUNIT_ASSERT(s.rep() == mpz_class("0x53696c766961206973206120676f6f6420667269656e64206f662049524d41"));

	silvia_integer_attribute i1(50);
	silvia_integer_attribute i2(mpz_class("125126127128129130131132133134135136137138139140"));

	CPPUNIT_ASSERT(i1.rep() == mpz_class(50));
	CPPUNIT_ASSERT(i2.rep() == mpz_class("125126127128129130131132133134135136137138139140"));

	silvia_boolean_attribute b1(true);
	silvia_boolean_attribute b2(false);

	CPPUNIT_ASSERT(b1.rep() == mpz_class(1));
	CPPUNIT_ASSERT(b2.rep() == mpz_class(0));

	generic = &s;

	CPPUNIT_ASSERT(generic->is_of_type(SILVIA_STRING_ATTR) == true);
	CPPUNIT_ASSERT(generic->is_of_type(SILVIA_INT_ATTR) == false);
	CPPUNIT_ASSERT(generic->is_of_type(SILVIA_BOOL_ATTR) == false);
	CPPUNIT_ASSERT(generic->is_of_type(SILVIA_UNDEFINED_ATTR) == false);

	generic = &i1;

	CPPUNIT_ASSERT(generic->is_of_type(SILVIA_STRING_ATTR) == false);
	CPPUNIT_ASSERT(generic->is_of_type(SILVIA_INT_ATTR) == true);
	CPPUNIT_ASSERT(generic->is_of_type(SILVIA_BOOL_ATTR) == false);
	CPPUNIT_ASSERT(generic->is_of_type(SILVIA_UNDEFINED_ATTR) == false);

	generic = &b1;

	CPPUNIT_ASSERT(generic->is_of_type(SILVIA_STRING_ATTR) == false);
	CPPUNIT_ASSERT(generic->is_of_type(SILVIA_INT_ATTR) == false);
	CPPUNIT_ASSERT(generic->is_of_type(SILVIA_BOOL_ATTR) == true);
	CPPUNIT_ASSERT(generic->is_of_type(SILVIA_UNDEFINED_ATTR) == false);

	silvia_string_attribute t("Silvia is a good friend of IRMA");
	silvia_string_attribute u("Saskia is the most wonderful niece in the world");

	CPPUNIT_ASSERT(s.rep() == t.rep());
	CPPUNIT_ASSERT(s.rep() != u.rep());

	silvia_integer_attribute i3(50);
	silvia_integer_attribute i4(60);

	CPPUNIT_ASSERT(i1.rep() == i3.rep());
	CPPUNIT_ASSERT(i1.rep() != i4.rep());

	silvia_boolean_attribute b3(true);

	CPPUNIT_ASSERT(b1.rep() == b3.rep());
	CPPUNIT_ASSERT(b2.rep() != b3.rep());
	
	silvia_string_attribute s2;
	s2.from_rep(mpz_class("0x5468697320697320612072656372656174696f6e2074657374"));
	
	CPPUNIT_ASSERT(s2.get_value() == "This is a recreation test");
	
	silvia_string_attribute s3;
	s3.from_rep(mpz_class("0x0000000000000000000000000000000000000000000000000000000000796573"));
	
	CPPUNIT_ASSERT(s3.get_value() == "yes");
}

void type_tests::test_credential()
{
	silvia_string_attribute a1("The first attribute");
	silvia_integer_attribute a2(2);
	silvia_boolean_attribute a3(true);

	std::vector<silvia_attribute*> a;
	a.push_back(&a1);
	a.push_back(&a2);
	a.push_back(&a3);

	silvia_integer_attribute s(mpz_class("0xbd938b37f51018cf906f2562db7444bf384df6b2e74616473532c5a6d452954e"));

	silvia_credential c
	(
		s, 
		a,
		mpz_class("0xaca39364eb158ad06edaec05c3a87782d252706f60e960ad27a047ab7a4837e15ad108be29dc26960a9242b98ce8b3114b955c5ebffe1fbbd0cc9bda29222443ad0191c0575c20cae1d6c038fb54848569fa17fe645ec741f82b047b9c0dc538a32cbc53a4745d462f368c5c3514286cb678eddd40fd3b522b67df6f368847fe24f684464c725bde197c47bf833ba9d995440c20420c3f475f1d6879bef6fc16951138d10d520f654f848d78825765ef51f5c742d68c9348c308909968b118ef22ffc78674554319e2c5e1172ac3c279b3dc4c1b2367d0565b2d2dae043887003ac8297ca211df9ffd1450d7ee9b59eec9aa4b3907636620f183cece6267dd1b"),
		mpz_class("0x100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000712f16428b4401e7815ba40924eaaf"),
		mpz_class("0x9cc115a651868301bd0be461631ad8dae969f9fa383021435beaabd65735c8c0ddb6cf7ae3bb3e626a8f75a21970bb618d0329eeced863e7848a3d56c9c7131b16be42bb3ee36e884d7e84a73ac00af8c2d944f02ce9b93adb04f440a38f2083cbab594915d72ddb3c0c56ac17beaf12ffabba51f111c56d12c3d332c68006bbf914dd3aa0044287cccad0636a4396d8fe44616a4e3b76606269d256f58843cd39441124577338ef6f1839d4849fdd60201be7fca916ada5e45c8db8578f4c3d343435b1ad585dc3a37a6933426044b8e467cc5145769501ca90b84c12a45b812bb8f344bc496ce9306e216d584a79151036e76d6541d0fe9abc925fa8cbf7a379e88722cd3263323a38f31892d92133bb76b40a77e8b5e440fc729b4daf0bd436e17071f0cfe7aa59ab044b9c0cc4271fab13ecd67176da46023649f8b9b0f3f34d1d528984c8b8e5b00155a178e29241f6e65bd")
	);

	CPPUNIT_ASSERT(c.num_attributes() == 3);

	CPPUNIT_ASSERT(c.get_attribute(0)->is_of_type(SILVIA_STRING_ATTR) == true);
	CPPUNIT_ASSERT(c.get_attribute(1)->is_of_type(SILVIA_INT_ATTR) == true);
	CPPUNIT_ASSERT(c.get_attribute(2)->is_of_type(SILVIA_BOOL_ATTR) == true);

	CPPUNIT_ASSERT(c.get_secret().rep() == s.rep());
	
	CPPUNIT_ASSERT(c.get_A() == mpz_class("0xaca39364eb158ad06edaec05c3a87782d252706f60e960ad27a047ab7a4837e15ad108be29dc26960a9242b98ce8b3114b955c5ebffe1fbbd0cc9bda29222443ad0191c0575c20cae1d6c038fb54848569fa17fe645ec741f82b047b9c0dc538a32cbc53a4745d462f368c5c3514286cb678eddd40fd3b522b67df6f368847fe24f684464c725bde197c47bf833ba9d995440c20420c3f475f1d6879bef6fc16951138d10d520f654f848d78825765ef51f5c742d68c9348c308909968b118ef22ffc78674554319e2c5e1172ac3c279b3dc4c1b2367d0565b2d2dae043887003ac8297ca211df9ffd1450d7ee9b59eec9aa4b3907636620f183cece6267dd1b"));

	CPPUNIT_ASSERT(c.get_e() == mpz_class("0x100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000712f16428b4401e7815ba40924eaaf"));

	CPPUNIT_ASSERT(c.get_v() == mpz_class("0x9cc115a651868301bd0be461631ad8dae969f9fa383021435beaabd65735c8c0ddb6cf7ae3bb3e626a8f75a21970bb618d0329eeced863e7848a3d56c9c7131b16be42bb3ee36e884d7e84a73ac00af8c2d944f02ce9b93adb04f440a38f2083cbab594915d72ddb3c0c56ac17beaf12ffabba51f111c56d12c3d332c68006bbf914dd3aa0044287cccad0636a4396d8fe44616a4e3b76606269d256f58843cd39441124577338ef6f1839d4849fdd60201be7fca916ada5e45c8db8578f4c3d343435b1ad585dc3a37a6933426044b8e467cc5145769501ca90b84c12a45b812bb8f344bc496ce9306e216d584a79151036e76d6541d0fe9abc925fa8cbf7a379e88722cd3263323a38f31892d92133bb76b40a77e8b5e440fc729b4daf0bd436e17071f0cfe7aa59ab044b9c0cc4271fab13ecd67176da46023649f8b9b0f3f34d1d528984c8b8e5b00155a178e29241f6e65bd"));
}

