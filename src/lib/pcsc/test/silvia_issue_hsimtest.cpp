/* $Id$ */

/*
 * Copyright (c) 2013 Pim Vullers
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
 silvia_issue_pcsctest.cpp

 PCSC issuance test application
 *****************************************************************************/
 
#include "silvia_apdu.h"
#include "silvia_verifier.h"
#include "silvia_issuer.h"
#include "silvia_issuer_keygen.h"
#include "silvia_irma_verifier.h"
#include "silvia_parameters.h"
#include "silvia_rand.h"
#include "silvia_macros.h"
#include <stdio.h>
#include <vector>
#include <utility>

void exchange_apdu(std::string cmd_name, bytestring apdu, bytestring& data, unsigned short& sw, unsigned short expected_sw, bool verbose = true)
{
	if (verbose) {
		printf("Transmitting %s command...\n", cmd_name.c_str());
		printf("Send: %s\n", apdu.hex_str().c_str());
	}
		
	std::string cmd("hterm -sim sim -selectaid \"49524D4163617264\" -apdu \"" + apdu.hex_str() + "\" | sed -e 's/.*=> \\[ //' -e 's/ ]//' -e 's/[ \\n]//g'");
//	printf("CMD: %s\n", cmd.c_str());
	FILE* hsim = popen(cmd.c_str(), "r");
	if (!hsim) {
		printf("Failed to connect to hterm/hsim.");
		return;
	}
	
	bytestring response("");
	char buffer[4096];
	int size;
    	while(!feof(hsim)) {
        	size=(int)fread(buffer, 1, 4096, hsim);
		buffer[size-2] = '\0';
		bytestring resp(buffer);
	        response += resp;
	}
	pclose(hsim);
	data = response;

	sw = data[data.size() - 2] << 8;
	sw += data[data.size() - 1];
	
	data.resize(data.size() - 2);

	if (verbose) {
		printf("Recv: %s (0x%04X)\n\n", data.hex_str().c_str(), sw);
	}
	
	if (expected_sw != 0 && sw != expected_sw)
	{
		printf("Unexpected response status word\n");
		
		exit(-1);
	}
}

bytestring fixLength(bytestring str, int length) {
	while (str.size() < length) str = "00" + str;
	return str;
}

int test_full_issuance(unsigned short id)
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
	// Issuer
	////////////////////////////////////////////////////////////////////
	
	silvia_pub_key* pub_key;
	silvia_priv_key* priv_key;
	
	silvia_issuer_keyfactory::i()->generate_keypair(6, &pub_key, &priv_key);
	
	silvia_issuer issuer(pub_key, priv_key);

	////////////////////////////////////////////////////////////////////
	// Test attributes
	////////////////////////////////////////////////////////////////////
	
	silvia_integer_attribute m1(0x3EEE);
	silvia_string_attribute m2("yes");
	silvia_string_attribute m3("yes");
	silvia_string_attribute m4("yes");
	silvia_string_attribute m5("yes");
	
	std::vector<silvia_attribute*> attributes;
	attributes.push_back(&m1);
	attributes.push_back(&m2);
	attributes.push_back(&m3);
	attributes.push_back(&m4);
	attributes.push_back(&m5);

	issuer.set_attributes(attributes);

	mpz_class context_mpz = silvia_rng::i()->get_random(SYSPAR(l_H));
	bytestring context(context_mpz);
	bytestring bsid(id);
	bsid = fixLength(bsid, 2);
	bytestring size = "0005";
	bytestring flags = "000000";
	bytestring timestamp = "01020304";
	
	context = fixLength(context, SYSPAR(l_H)/8);

	////////////////////////////////////////////////////////////////////
	// Step 1: select application
	////////////////////////////////////////////////////////////////////
	
	bytestring data;
	unsigned short sw;
	
	
	////////////////////////////////////////////////////////////////////
	// Step 1.5: remove old
	////////////////////////////////////////////////////////////////////
	

	////////////////////////////////////////////////////////////////////
	// Step 2: log in
	////////////////////////////////////////////////////////////////////
	
	
	////////////////////////////////////////////////////////////////////
	// Step 3: start issuance
	////////////////////////////////////////////////////////////////////
	
	silvia_apdu issue_apdu(0x80, 0x10, 0x00, 0x00);
	issue_apdu.append_data(bsid);
	issue_apdu.append_data(size);
	issue_apdu.append_data(flags);
	issue_apdu.append_data(context);
	issue_apdu.append_data(timestamp);
	
	exchange_apdu("ISSUE CREDENTIAL", issue_apdu.get_apdu(), data, sw, 0x9000);
	
	////////////////////////////////////////////////////////////////////
	// Step 4: public key
	////////////////////////////////////////////////////////////////////
	
	silvia_apdu n_apdu(0x80, 0x11, 0x00, 0x00);
	bytestring n(pub_key->get_n());
	n = fixLength(n, SYSPAR(l_n)/8);
	n_apdu.append_data(n);
	exchange_apdu("ISSUE PUBKEY(n)", n_apdu.get_apdu(), data, sw, 0x9000);

	silvia_apdu S_apdu(0x80, 0x11, 0x01, 0x00);
	bytestring S(pub_key->get_S());
	S = fixLength(S, SYSPAR(l_n)/8);
	S_apdu.append_data(S);
	exchange_apdu("ISSUE PUBKEY(S)", S_apdu.get_apdu(), data, sw, 0x9000);

	silvia_apdu Z_apdu(0x80, 0x11, 0x02, 0x00);
	bytestring Z(pub_key->get_Z());
	Z = fixLength(Z, SYSPAR(l_n)/8);
	Z_apdu.append_data(Z);
	exchange_apdu("ISSUE PUBKEY(Z)", Z_apdu.get_apdu(), data, sw, 0x9000);

	for (int i = 0; i < pub_key->get_R().size(); i++) {
		silvia_apdu R_apdu(0x80, 0x11, 0x03, i);
		bytestring R(pub_key->get_R()[i]);
		R = fixLength(R, SYSPAR(l_n)/8);
		R_apdu.append_data(R);
		exchange_apdu("ISSUE PUBKEY(R)", R_apdu.get_apdu(), data, sw, 0x9000);
	}

	////////////////////////////////////////////////////////////////////
	// Step 5: attributes
	////////////////////////////////////////////////////////////////////
	
	for (int i = 0; i < attributes.size(); i++) {
		silvia_apdu attr_apdu(0x80, 0x12, i + 1, 0x00);
		bytestring attr(attributes[i]->rep());
		attr = fixLength(attr, SYSPAR(l_m)/8);
		attr_apdu.append_data(attr);
		exchange_apdu("ISSUE ATTRIBUTES", attr_apdu.get_apdu(), data, sw, 0x9000);
	}

	////////////////////////////////////////////////////////////////////
	// Step 6: round 1
	////////////////////////////////////////////////////////////////////
	
	silvia_apdu n1_apdu(0x80, 0x1A, 0x00, 0x00);
	bytestring n1(issuer.get_issuer_nonce());
	n1 = fixLength(n1, SYSPAR(l_statzk)/8);
	n1_apdu.append_data(n1);
	exchange_apdu("ISSUE COMMITMENT(U)", n1_apdu.get_apdu(), data, sw, 0x9000);
	mpz_class U = data.mpz_val();


	exchange_apdu("ISSUE_COMMITMENT(c)", "801b0100", data, sw, 0x9000);
	mpz_class c = data.mpz_val();
	
	exchange_apdu("ISSUE_COMMITMENT(v'^)", "801b0200", data, sw, 0x9000);
	mpz_class vPrime_hat = data.mpz_val();
	
	exchange_apdu("ISSUE_COMMITMENT(s^)", "801b0300", data, sw, 0x9000);
	mpz_class s_hat = data.mpz_val();

	printf("Commitment verification... ");
	if (!issuer.submit_and_verify_commitment(context_mpz, U, c, vPrime_hat, s_hat)) {
		printf("FAILED\n");
		silvia_system_parameters::i()->reset();
		exit(-1);
		return 1;
	} else {
		printf("OK\n");
	}

	
	////////////////////////////////////////////////////////////////////
	// Step 7: round 2 & 3
	////////////////////////////////////////////////////////////////////
	
	exchange_apdu("ISSUE_NONCE(n2)", "801c0000", data, sw, 0x9000);
	mpz_class n2 = data.mpz_val();

	mpz_class A, e, v_prime_prime;
	issuer.compute_signature(A, e, v_prime_prime);

	mpz_class c2, e_hat;
	issuer.prove_signature(n2, context_mpz, c2, e_hat);

	silvia_apdu A_apdu(0x80, 0x1D, 0x01, 0x00);
	bytestring bsA(A);
	bsA = fixLength(bsA, SYSPAR(l_n)/8);
	A_apdu.append_data(bsA);
	exchange_apdu("ISSUE SIGNATURE(A)", A_apdu.get_apdu(), data, sw, 0x9000);

	silvia_apdu e_apdu(0x80, 0x1D, 0x02, 0x00);
	bytestring bse(e);
	bse = fixLength(bse, SYSPAR(l_e)/8);
	e_apdu.append_data(bse);
	exchange_apdu("ISSUE SIGNATURE(e)", e_apdu.get_apdu(), data, sw, 0x9000);

	silvia_apdu v_apdu(0x80, 0x1D, 0x03, 0x00);
	bytestring bsv(v_prime_prime);
	bsv = fixLength(bsv, SYSPAR(l_v)/8);
	v_apdu.append_data(bsv);
	exchange_apdu("ISSUE SIGNATURE(v)", v_apdu.get_apdu(), data, sw, 0x9000);

	silvia_apdu c_apdu(0x80, 0x1D, 0x04, 0x00);
	bytestring bsc(c2);
	bsc = fixLength(bsc, SYSPAR(l_H)/8);
	c_apdu.append_data(bsc);
	exchange_apdu("ISSUE SIGNATURE(c)", c_apdu.get_apdu(), data, sw, 0x9000);

	silvia_apdu eH_apdu(0x80, 0x1D, 0x05, 0x00);
	bytestring bseH(e_hat);
	bseH = fixLength(bseH, SYSPAR(l_n)/8);
	eH_apdu.append_data(bseH);
	exchange_apdu("ISSUE SIGNATURE(e^)", eH_apdu.get_apdu(), data, sw, 0x9000);

	exchange_apdu("ISSUE VERIFY", "801F0000", data, sw, 0);
	if (sw != 0x9000) {
		silvia_system_parameters::i()->reset();
		return 2;
	}

	////////////////////////////////////////////////////////////////////
	// System parameters
	////////////////////////////////////////////////////////////////////
	
	silvia_system_parameters::i()->reset();

	return 0;
}

int main(int argc, char* argv[])
{
	int fail_commitment_count = 0;
	int fail_verify_count = 0;
	int ok_count = 0;
	
	bytestring data;
	unsigned short sw;

	for (int i = 0; i < 100; i++) {
		if (i % 10 == 0) {
			exchange_apdu("SELECT", "00A404000849524D416361726400", data, sw, 0x9000);
			exchange_apdu("VERIFY PIN", "00200000083030303000000000", data, sw, 0x9000);
			exchange_apdu("VERIFY PIN", "00200001083030303030300000", data, sw, 0x9000);
		}

		printf("\nRemoving credentials... ");
		for (unsigned short j = 1; j <= 10; j++) {
			printf("%d ", j);
			exchange_apdu("REMOVE CRED", "8031" + fixLength(bytestring(j),2), data, sw, 0, false);
		}
		printf("... Done.\n\n");

		for (unsigned short j = 1; j <= 10; j++) {
			printf("Credential ID %d\n", j);
			switch (test_full_issuance(j)) {
				case 0:
					ok_count++;
					break;
				case 1:
					fail_commitment_count++;
					break;
				case 2:
					fail_verify_count++;
					break;
				default:
					printf("Unknown result\n");
					break;
			}
		
			printf("\nSuccesses: %d, failures %d, %d\n", ok_count, fail_commitment_count, fail_verify_count);
		}
	}
	
	return 0;
}
	
