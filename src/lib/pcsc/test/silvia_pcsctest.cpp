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
 silvia_pcsctest.cpp

 PCSC test application
 *****************************************************************************/
 
#include "silvia_card.h"
#include "silvia_apdu.h"
#include "silvia_verifier.h"
#include "silvia_parameters.h"
#include "silvia_rand.h"
#include <stdio.h>
 
silvia_card* get_card()
{
	silvia_card* card;
	
	printf("Waiting for card... "); fflush(stdout);
	
	if (!silvia_card_monitor::i()->wait_for_card(&card))
	{
		printf("FAILED\n");
	}
	else
	{
		printf("OK\n");
	}
	
	printf("Card inserted in reader \"%s\"\n", card->get_reader_name().c_str());
	
	return card;
}

void test_select_apdu(silvia_card* card)
{
	bytestring select = "00A404000849524D416361726400";
	bytestring data;
	unsigned short sw;
	
	printf("Transmitting SELECT command...\n");
	printf("Send: %s\n", select.hex_str().c_str());
	
	if (!card->transmit(select, data, sw))
	{
		printf("FAILED\n");
		
		return;
	}
	
	printf("Recv: %s (0x%04X)\n", data.hex_str().c_str(), sw);
}

void test_validate_admin_pin(silvia_card* card)
{
	bytestring verify_pin = "00200001083030303030300000";
	bytestring data;
	unsigned short sw;
	
	printf("Transmitting VERIFY PIN command...\n");
	printf("Send: %s\n", verify_pin.hex_str().c_str());
	
	if (!card->transmit(verify_pin, data, sw))
	{
		printf("FAILED\n");
		
		return;
	}
	
	printf("Recv: %s (0x%04X)\n", data.hex_str().c_str(), sw);
}

void test_get_credentials(silvia_card* card)
{
	bytestring get_credentials = "803A0000";
	bytestring data;
	unsigned short sw;

	printf("Transmitting GET CREDENTIALS command...\n");
	printf("Send: %s\n", get_credentials.hex_str().c_str());
	
	if (!card->transmit(get_credentials, data, sw))
	{
		printf("FAILED\n");
		
		return;
	}
	
	printf("Recv: %s (0x%04X)\n", data.hex_str().c_str(), sw);
}

void test_verify_pin(silvia_card* card)
{
	bytestring verify_pin = "00200000083030303000000000";
	bytestring data;
	unsigned short sw;
	
	printf("Transmitting VERIFY PIN command...\n");
	printf("Send: %s\n", verify_pin.hex_str().c_str());
	
	if (!card->transmit(verify_pin, data, sw))
	{
		printf("FAILED\n");
		
		return;
	}
	
	printf("Recv: %s (0x%04X)\n", data.hex_str().c_str(), sw);
}

void test_prove_credential(silvia_card* card)
{
	silvia_apdu prove_credential(0x80, 0x20, 0x00, 0x00);				// PROVE CREDENTIAL
	prove_credential.append_data("000a");								// credential ID
	prove_credential.append_data("1122112211221122112211221122112211221122112211221122112211221122");
																		// context
	prove_credential.append_data("003e");								// attribute mask
	prove_credential.append_data("01020304");							// time stamp
	
	bytestring data;
	unsigned short sw;
	
	printf("Transmitting PROVE CREDENTIAL command...\n");
	printf("Send: %s\n", prove_credential.get_apdu().hex_str().c_str());
		
	if (!card->transmit(prove_credential.get_apdu(), data, sw))
	{
		printf("FAILED\n");
		
		return;
	}
	
	printf("Recv: %s (0x%04X)\n", data.hex_str().c_str(), sw);
}

void test_prove_commitment(silvia_card* card)
{
	silvia_apdu prove_commitment(0x80, 0x2a, 0x00, 0x00);
	prove_commitment.append_data("aabbaabbaabbaabbaabb");	// n1
	
	bytestring data;
	unsigned short sw;
	
	printf("Transmitting PROVE COMMITMENT command...\n");
	printf("Send: %s\n", prove_commitment.get_apdu().hex_str().c_str());
		
	if (!card->transmit(prove_commitment.get_apdu(), data, sw))
	{
		printf("FAILED\n");
		
		return;
	}
	
	printf("Recv: %s (0x%04X)\n", data.hex_str().c_str(), sw);
}

void test_get_signature(silvia_card* card)
{
	bytestring prove_signature_A_prime = "802b0100";
	bytestring prove_signature_e_hat = "802b0200";
	bytestring prove_signature_v_hat = "802b0300";
	
	bytestring data;
	unsigned short sw;
	
	printf("Transmitting PROVE SIGNATURE (A') command...\n");
	printf("Send: %s\n", prove_signature_A_prime.hex_str().c_str());
	
	if (!card->transmit(prove_signature_A_prime, data, sw))
	{
		printf("FAILED\n");
		
		return;
	}
	
	printf("Recv: %s (0x%04X)\n", data.hex_str().c_str(), sw);
	
	printf("Transmitting PROVE SIGNATURE (e^) command...\n");
	printf("Send: %s\n", prove_signature_e_hat.hex_str().c_str());
	
	if (!card->transmit(prove_signature_e_hat, data, sw))
	{
		printf("FAILED\n");
		
		return;
	}
	
	printf("Recv: %s (0x%04X)\n", data.hex_str().c_str(), sw);
	
	printf("Transmitting PROVE SIGNATURE (v^) command...\n");
	printf("Send: %s\n", prove_signature_v_hat.hex_str().c_str());
	
	if (!card->transmit(prove_signature_v_hat, data, sw))
	{
		printf("FAILED\n");
		
		return;
	}
	
	printf("Recv: %s (0x%04X)\n", data.hex_str().c_str(), sw);
}

void test_get_response(silvia_card* card)
{
	for (int i = 0; i < 6; i++)
	{
		silvia_apdu get_response(0x80, 0x2C, i, 0x00);
		
		bytestring data;
		unsigned short sw;
		
		printf("Transmitting GET RESPONSE command...\n");
		printf("Send: %s\n", get_response.get_apdu().hex_str().c_str());
			
		if (!card->transmit(get_response.get_apdu(), data, sw))
		{
			printf("FAILED\n");
			
			return;
		}
		
		printf("Recv: %s (0x%04X)\n", data.hex_str().c_str(), sw);
	}
}

void exchange_apdu(silvia_card* card, std::string cmd_name, bytestring apdu, bytestring& data, unsigned short& sw, unsigned short expected_sw)
{
	printf("Transmitting %s command...\n", cmd_name.c_str());
	printf("Send: %s\n", apdu.hex_str().c_str());
		
	if (!card->transmit(apdu, data, sw))
	{
		printf("FAILED\n");
		
		return;
	}
	
	printf("Recv: %s (0x%04X)\n\n", data.hex_str().c_str(), sw);
	
	if (sw != expected_sw)
	{
		printf("Unexpected response status word\n");
		
		exit(-1);
	}
}

bool test_full_proof(silvia_card* card)
{
	printf("\n\n\n");
	printf("TESTING FULL PROOF\n\n\n");
	
	////////////////////////////////////////////////////////////////////
	// System parameters
	////////////////////////////////////////////////////////////////////
	
	silvia_system_parameters::i()->set_l_n(1024);
	silvia_system_parameters::i()->set_l_m(256);
	silvia_system_parameters::i()->set_l_statzk(80);
	silvia_system_parameters::i()->set_l_H(256);
	silvia_system_parameters::i()->set_l_v(1700);
	silvia_system_parameters::i()->set_l_e(597);
	silvia_system_parameters::i()->set_l_e_prime(120);
	silvia_system_parameters::i()->set_hash_type("sha256");
	
	////////////////////////////////////////////////////////////////////
	// Issuer public key
	////////////////////////////////////////////////////////////////////
	
	mpz_class n("96063359353814070257464989369098573470645843347358957127875426328487326540633303185702306359400766259130239226832166456957259123554826741975265634464478609571816663003684533868318795865194004795637221226902067194633407757767792795252414073029114153019362701793292862118990912516058858923030408920700061749321");
	mpz_class Z("44579327840225837958738167571392618381868336415293109834301264408385784355849790902532728798897199236650711385876328647206143271336410651651791998475869027595051047904885044274040212624547595999947339956165755500019260290516022753290814461070607850420459840370288988976468437318992206695361417725670417150636");
	mpz_class S("68460510129747727135744503403370273952956360997532594630007762045745171031173231339034881007977792852962667675924510408558639859602742661846943843432940752427075903037429735029814040501385798095836297700111333573975220392538916785564158079116348699773855815825029476864341585033111676283214405517983188761136");
	std::vector<mpz_class> R;
	
	R.push_back(mpz_class("75350858539899247205099195870657569095662997908054835686827949842616918065279527697469302927032348256512990413925385972530386004430200361722733856287145745926519366823425418198189091190950415327471076288381822950611094023093577973125683837586451857056904547886289627214081538422503416179373023552964235386251"));
	R.push_back(mpz_class("16493273636283143082718769278943934592373185321248797185217530224336539646051357956879850630049668377952487166494198481474513387080523771033539152347804895674103957881435528189990601782516572803731501616717599698546778915053348741763191226960285553875185038507959763576845070849066881303186850782357485430766"));
	R.push_back(mpz_class("13291821743359694134120958420057403279203178581231329375341327975072292378295782785938004910295078955941500173834360776477803543971319031484244018438746973179992753654070994560440903251579649890648424366061116003693414594252721504213975050604848134539324290387019471337306533127861703270017452296444985692840"));
	R.push_back(mpz_class("86332479314886130384736453625287798589955409703988059270766965934046079318379171635950761546707334446554224830120982622431968575935564538920183267389540869023066259053290969633312602549379541830869908306681500988364676409365226731817777230916908909465129739617379202974851959354453994729819170838277127986187"));
	R.push_back(mpz_class("68324072803453545276056785581824677993048307928855083683600441649711633245772441948750253858697288489650767258385115035336890900077233825843691912005645623751469455288422721175655533702255940160761555155932357171848703103682096382578327888079229101354304202688749783292577993444026613580092677609916964914513"));
	R.push_back(mpz_class("65082646756773276491139955747051924146096222587013375084161255582716233287172212541454173762000144048198663356249316446342046266181487801411025319914616581971563024493732489885161913779988624732795125008562587549337253757085766106881836850538709151996387829026336509064994632876911986826959512297657067426387"));
	
	silvia_pub_key pubkey(n, S, Z, R);
	
	silvia_verifier verifier(&pubkey);
	
	////////////////////////////////////////////////////////////////////
	// Step 1: select application
	////////////////////////////////////////////////////////////////////
	
	bytestring data;
	unsigned short sw;
	
	exchange_apdu(card, "SELECT", "00A404000849524D416361726400", data, sw, 0x9000);
	
	////////////////////////////////////////////////////////////////////
	// Step 2: log in
	////////////////////////////////////////////////////////////////////
	
	exchange_apdu(card, "VERIFY PIN", "00200000083030303000000000", data, sw, 0x9000);
	
	////////////////////////////////////////////////////////////////////
	// Step 3: start proof
	////////////////////////////////////////////////////////////////////
	
	mpz_class context_mpz = silvia_rng::i()->get_random(SYSPAR(l_H));
	bytestring context(context_mpz);
	bytestring id = "000a"; // age credential
	bytestring D_val = "0010"; // disclose "over 18"
	bytestring timestamp = "01020304";
	
	while (context.size() < 32) context = "00" + context;
	
	silvia_apdu prove_apdu(0x80, 0x20, 0x00, 0x00);
	prove_apdu.append_data(id);
	prove_apdu.append_data(context);
	prove_apdu.append_data(D_val);
	prove_apdu.append_data(timestamp);
	
	exchange_apdu(card, "PROVE CREDENTIAL", prove_apdu.get_apdu(), data, sw, 0x9000);
	
	////////////////////////////////////////////////////////////////////
	// Step 4: send nonce and get commitment hash
	////////////////////////////////////////////////////////////////////
	
	mpz_class n1 = verifier.get_verifier_nonce();
	bytestring n1_val(n1);
	
	silvia_apdu commit_apdu(0x80, 0x2a, 0x00, 0x00);
	commit_apdu.append_data(n1_val);
	
	exchange_apdu(card, "PROVE COMMITMENT", commit_apdu.get_apdu(), data, sw, 0x9000);
	
	mpz_class c = data.mpz_val();
	
	////////////////////////////////////////////////////////////////////
	// Step 5: retrieve the signature data
	////////////////////////////////////////////////////////////////////
	
	exchange_apdu(card, "PROVE SIGNATURE A'", "802b0100", data, sw, 0x9000);
	mpz_class A_prime = data.mpz_val();
	
	exchange_apdu(card, "PROVE SIGNATURE e^", "802b0200", data, sw, 0x9000);
	mpz_class e_hat = data.mpz_val();
	
	exchange_apdu(card, "PROVE SIGNATURE v'^", "802b0300", data, sw, 0x9000);
	mpz_class v_prime_hat = data.mpz_val();
	
	////////////////////////////////////////////////////////////////////
	// Step 6: retrieve the attribute values
	////////////////////////////////////////////////////////////////////
	
	std::vector<mpz_class> a_i_hat;
	std::vector<silvia_attribute*> a_i;
	
	// Master secret
	exchange_apdu(card, "GET RESPONSE", "802C0000", data, sw, 0x9000);
	a_i_hat.push_back(data.mpz_val());
	
	// Expiry
	exchange_apdu(card, "GET RESPONSE", "802C0100", data, sw, 0x9000);
	a_i_hat.push_back(data.mpz_val());
	
	// Over 12
	exchange_apdu(card, "GET RESPONSE", "802C0200", data, sw, 0x9000);
	a_i_hat.push_back(data.mpz_val());
	
	// Over 16
	exchange_apdu(card, "GET RESPONSE", "802C0300", data, sw, 0x9000);
	a_i_hat.push_back(data.mpz_val());
	
	// Over 18
	exchange_apdu(card, "GET RESPONSE", "802C0400", data, sw, 0x9000);
	silvia_string_attribute over18;
	over18.from_rep(data.mpz_val());
	a_i.push_back(&over18);
	
	// Over 21
	exchange_apdu(card, "GET RESPONSE", "802C0500", data, sw, 0x9000);
	a_i_hat.push_back(data.mpz_val());
	
	////////////////////////////////////////////////////////////////////
	// Step 7: verify the proof
	////////////////////////////////////////////////////////////////////
	
	// Proof specification
	std::vector<bool> D;
	D.push_back(false);		// expiry
	D.push_back(false);		// over 12
	D.push_back(false);		// over 16
	D.push_back(true);		// over 18
	D.push_back(false);		// over 21
	
	printf("Proof verification... ");
	
	bool rv;
	
	if (!verifier.verify(D, context.mpz_val(), c, A_prime, e_hat, v_prime_hat, a_i_hat, a_i))
	{
		printf("FAILED\n");
		rv = false;
	}
	else
	{
		printf("OK!\n");
		rv = true;
	}
	
	////////////////////////////////////////////////////////////////////
	// System parameters
	////////////////////////////////////////////////////////////////////
	
	silvia_system_parameters::i()->reset();
	
	return rv;
}

int main(int argc, char* argv[])
{
	silvia_card* card = get_card();
	
	test_select_apdu(card);
	
	test_validate_admin_pin(card);
	
	test_get_credentials(card);
	
	test_verify_pin(card);
	
	test_prove_credential(card);
	
	test_prove_commitment(card);
	
	test_get_signature(card);
	
	test_get_response(card);

	int fail_count = 0;
	int ok_count = 0;
	
	for (int i = 0; i < 100; i++)
	{
		if (test_full_proof(card))
		{
			ok_count++;
		}
		else
		{
			fail_count++;
		}
		
		printf("\nSuccesses: %d, failures %d\n", ok_count, fail_count);
	}
	
	delete card;
	
	return 0;
}
