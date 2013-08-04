/* $Id$ */

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
 xmltests.h

 Tests XML readers
 *****************************************************************************/

#include <stdlib.h>
#include <cppunit/extensions/HelperMacros.h>
#include <string>
#include <gmpxx.h>
#include "xmltests.h"
#include "silvia_types.h"
#include "silvia_macros.h"
#include "silvia_idemix_xmlreader.h"
#include "silvia_irma_xmlreader.h"
#include <stdio.h>

CPPUNIT_TEST_SUITE_REGISTRATION(xml_tests);

void xml_tests::setUp()
{
}

void xml_tests::tearDown()
{
}

void xml_tests::test_idemix_read_pubkey()
{
	silvia_pub_key* pub_key = silvia_idemix_xmlreader::i()->read_idemix_pubkey("ipk.xml");
	
	CPPUNIT_ASSERT(pub_key != NULL);
	
	CPPUNIT_ASSERT(pub_key->get_S() == mpz_class("0x617db25740673217df74bddc8d8ac1345b54b9aea903451ec2c6efbe994301f9cabb254d14e4a9fd2cd3fcc2c0efc87803f0959c9550b2d2a2ee869bcd6c5df7b9e1e24c18e0d2809812b056ce420a75494f9c09c3405b4550fd97d57b4930f75cd9c9ce0a820733cb7e6fc1eeaf299c3844c1c9077ac705b774d7a20e77ba30"));
	CPPUNIT_ASSERT(pub_key->get_Z() == mpz_class("0x3f7baa7b26d110054a2f427939e61ac4e844139ceebea24e5c6fb417ffeb8f38272fbfeec203db43a2a498c49b7746b809461b3d1f514308eeb31f163c5b6fd5e41fff1eb2c5987a79496161a56e595bc9271aaa65d2f6b72f561a78dd6115f5b706d92d276b95b1c90c49981fe79c23a19a2105032f9f621848bc57352ab2ac"));
	CPPUNIT_ASSERT(pub_key->get_n() == mpz_class("0x88cc7bd5eaa39006a63d1dba18bdaf00130725597a0a46f0baccef163952833bcbdd4070281cc042b4255488d0e260b4d48a31d94bca67c854737d37890c7b21184a053cd579176681093ab0ef0b8db94afd1812a78e1e62ae942651bb909e6f5e5a2cef6004946cca3f66ec21cb9ac01ff9d3e88f19ac27fc77b1903f141049"));
	CPPUNIT_ASSERT(pub_key->get_R()[0] == mpz_class("0x6b4d9d7d654e4b1285d4689e12d635d4af85167460a3b47db9e7b80a4d476dbeec0b8960a4acaecf25e18477b953f028bd71c6628dd2f047d9c0a6ee8f2bc7a8b34821c14b269dbd8a95dccd5620b60f64b132e09643cfce900a3045331207f794d4f7b4b0513486cb04f76d62d8b14b5f031a8ad9fff3fab8a68e74593c5d8b"));
	CPPUNIT_ASSERT(pub_key->get_R()[1] == mpz_class("0x177cb93935bb62c52557a8dd43075aa6dcdd02e2a004c56a81153595849a476c515a1fae9e596c22be960d3e963ecfac68f638ebf89642798ccae946f2f179d30abe0eda9a44e15e9cd24b522f6134b06ac09f72f04614d42fdbdb36b09f60f7f8b1a570789d861b7dbd40427254f0336d0923e1876527525a09cdab261ea7ee"));
	CPPUNIT_ASSERT(pub_key->get_R()[2] == mpz_class("0x12ed9d5d9c9960bace45b7471ed93572ea0b82c611120127701e4ef22a591cdc173136a468926103736a56713fef3111fde19e67ce632ab140a6ff6e09245ac3d6e022cd44a7cc36bcbe6b2189960d3d47513ab2610f27d272924a84154646027b73893d3ee8554767318942a8403f0cd2a41264814388be4df345e479ef52a8"));
	CPPUNIT_ASSERT(pub_key->get_R()[3] == mpz_class("0x7af1083437cdac568ff1727d9c8ac4768a15912b03a8814839cf053c85696df3a5681558f06bad593f8a09c4b9c3805464935e0372cbd235b18686b540963eb9310f9907077e36eed0251d2cf1d2ddd6836cf793ed23d266080bf43c31cf3d304e2055ef44d454f477354664e1025b3f134ace59272f07d0fd4995bdaaccdc0b"));
	CPPUNIT_ASSERT(pub_key->get_R()[4] == mpz_class("0x614bf5243c26d62e8c7c9b0fae9c57f44b05714894c3dcf583d9797c423c1635f2e4f1697e92771eb98cf36999448cefc20cb6e10931ded3927db0dff56e18bd3a6096f2ff1bff1a703f3cce6f37d589b5626354df0db277ef73da8a2c7347689b79130559fb94b6260c13d8dc7d264ba26953b906488b87cdc9dfd0bc69c551"));
	CPPUNIT_ASSERT(pub_key->get_R()[5] == mpz_class("0x5cae46a432be9db72f3b106e2104b68f361a9b3e7b06bbe3e52e60e69832618b941c952aa2c6eeffc222311ebbab922f7020d609d1435a8f3f941f4373e408be5febaf471d05c1b91030789f7fea450f61d6cb9a4dd8642253327e7ebf49c1600c2a075ec9b9dec196ddbdc373c29d1af5cead34fa6993b8cdd739d04ea0d253"));
	CPPUNIT_ASSERT(pub_key->get_R()[6] == mpz_class("0x52e49fe8b12bfe9f12300ef5fbde1800d4611a587e9f4763c11e3476bba671bfd2e868436c9e8066f96958c897dd6d291567c0c490329793f35e925b77b304249ea6b30241f5d014e1c533eac27aa9d9fca7049d3a8d89058969fc2cd4dc63df38740701d5e2b7299c49ec6f190da19f4f6bc3834ec1ae145af51afeba027eaa"));
	CPPUNIT_ASSERT(pub_key->get_R()[7] == mpz_class("0x5aa7ee2ad981bee4e3d4df8f86414797a8a38706c84c9376d324070c908724bb89b224cb5ade8cddb0f65ebe9965f5c710c59704c88607e3c527d57a548e24904f4991383e5028535ae21d11d5bf87c3c5178e638ddf16e666ea31f286d6d1b3251e0b1470e621bee94cdfa1d2e47a86fd2f900d5ddcb42080dab583cbeeedf"));
	CPPUNIT_ASSERT(pub_key->get_R()[8] == mpz_class("0x73d3ab9008dc2bd65161a0d7bfc6c29669c975b54a1339d8385bc7d5dec88c6d4bd482bfbc7a7de44b016646b378b6a85fbc1219d351fe475dc178f90df4961ca980eb4f157b764ec3ecf19604fede0551aa42fb12b7f19667ac9f2c46d1185e66072ea709cc0d9689ce721a47d54c028d7b0b01aeec1c4c9a03979be9080c21"));
	CPPUNIT_ASSERT(pub_key->get_R()[9] == mpz_class("0x33f10ab2d18b94d870c684b5436b38ac419c08fb065a2c608c4e2e2060fe436945a15f8d80f373b35c3230654a92f99b1a1c8d5bb10b83646a112506022af7d4d09f7403ec5aecdb077da945fe0be661bafeddddc5e43a4c5d1a0b28ae2aa838c6c8a7ae3df150dbd0a207891f1d6c4001b88d1d91cf380ee15e4e632f33bd02"));
	
	delete pub_key;
}

void xml_tests::test_idemix_read_privkey()
{
	silvia_priv_key* priv_key = silvia_idemix_xmlreader::i()->read_idemix_privkey("isk.xml");
	
	CPPUNIT_ASSERT(priv_key != NULL);
	
	CPPUNIT_ASSERT(priv_key->get_p()       == mpz_class("0xc742458f98bd17ea9380148f88b06290edca29ee5c2ea570a7ea36091acf2d06ca02570fdd2b8d73b5dd5e78eed2ada4f0b01a4cf200e2a507a64bb398f31b77"));
	CPPUNIT_ASSERT(priv_key->get_p_prime() == mpz_class("0x63a122c7cc5e8bf549c00a47c458314876e514f72e1752b853f51b048d67968365012b87ee95c6b9daeeaf3c776956d278580d267900715283d325d9cc798dbb"));
	CPPUNIT_ASSERT(priv_key->get_q()       == mpz_class("0xafc0f247dd7bfa36238ab5119d6e0ef19f46fd13d774103137d4712998f461fa8a753c0d850e178731b1c2839cf0d45f43e6ffa106a1adcb2ab98d3164d9a23f"));
	CPPUNIT_ASSERT(priv_key->get_q_prime() == mpz_class("0x57e07923eebdfd1b11c55a88ceb70778cfa37e89ebba08189bea3894cc7a30fd453a9e06c2870bc398d8e141ce786a2fa1f37fd08350d6e5955cc698b26cd11f"));
}

void xml_tests::test_irma_read_verifier_spec()
{
	silvia_verifier_specification* spec = silvia_irma_xmlreader::i()->read_verifier_spec("id_agelower.xml", "vd_bar.xml");
	
	CPPUNIT_ASSERT(spec->get_verifier_name() == "Bar");
	CPPUNIT_ASSERT(spec->get_short_msg() == "Age: 18+");
	CPPUNIT_ASSERT(spec->get_verifier_id() == 801);
	CPPUNIT_ASSERT(spec->get_credential_id() == 10);
	CPPUNIT_ASSERT(spec->get_attribute_names()[0] == "expires");
	CPPUNIT_ASSERT(spec->get_attribute_names()[1] == "over12");
	CPPUNIT_ASSERT(spec->get_attribute_names()[2] == "over16");
	CPPUNIT_ASSERT(spec->get_attribute_names()[3] == "over18");
	CPPUNIT_ASSERT(spec->get_attribute_names()[4] == "over21");
	CPPUNIT_ASSERT(spec->get_D()[0] == true);
	CPPUNIT_ASSERT(spec->get_D()[1] == false);
	CPPUNIT_ASSERT(spec->get_D()[2] == false);
	CPPUNIT_ASSERT(spec->get_D()[3] == true);
	CPPUNIT_ASSERT(spec->get_D()[4] == false);
	
	CPPUNIT_ASSERT(spec != NULL);	
}
