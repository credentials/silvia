/* $Id$ */

/*
 * Copyright (c) 2013 Roland van Rijswijk-Deij, Pim Vullers
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
 
#include "silvia_apdu.h"
#include "silvia_verifier.h"
#include "silvia_issuer.h"
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
		
	std::string cmd("hterm -sim sim_verify -selectaid \"49524D4163617264\" -apdu \"" + apdu.hex_str() + "\" | sed -e 's/.*=> \\[ //' -e 's/ ]//' -e 's/[ \\n]//g'");
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

bool test_full_proof(mpz_class& n1_value, mpz_class& context_val, mpz_class& c_val, mpz_class& A_prime_val, mpz_class& e_hat_val, mpz_class& v_prime_hat_val, std::vector<mpz_class>& a_i_hat_val)
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
	
	exchange_apdu("SELECT", "00A404000849524D416361726400", data, sw, 0x9000);
	
	////////////////////////////////////////////////////////////////////
	// Step 2: log in
	////////////////////////////////////////////////////////////////////
	
	exchange_apdu("VERIFY PIN", "00200000083030303000000000", data, sw, 0x9000);
	
	////////////////////////////////////////////////////////////////////
	// Step 3: start proof
	////////////////////////////////////////////////////////////////////
	
	mpz_class context_mpz = silvia_rng::i()->get_random(SYSPAR(l_H));
	bytestring context(context_mpz);
	bytestring id = "000a"; // age credential
	bytestring D_val = "0012"; // disclose "expiry" and "over18"
	bytestring timestamp = "01020304";
	
	while (context.size() < 32) context = "00" + context;
	
	silvia_apdu prove_apdu(0x80, 0x20, 0x00, 0x00);
	prove_apdu.append_data(id);
	prove_apdu.append_data(D_val);
	prove_apdu.append_data(context);
	prove_apdu.append_data(timestamp);
	
	exchange_apdu("PROVE CREDENTIAL", prove_apdu.get_apdu(), data, sw, 0x9000);
	
	////////////////////////////////////////////////////////////////////
	// Step 4: send nonce and get commitment hash
	////////////////////////////////////////////////////////////////////
	
	mpz_class n1 = verifier.get_verifier_nonce();
	bytestring n1_val(n1);
	
	while (n1_val.size() < 10) n1_val = "00" + n1_val;
	
	silvia_apdu commit_apdu(0x80, 0x2a, 0x00, 0x00);
	commit_apdu.append_data(n1_val);
	
	exchange_apdu("PROVE COMMITMENT", commit_apdu.get_apdu(), data, sw, 0x9000);
	
	mpz_class c = data.mpz_val();
	
	////////////////////////////////////////////////////////////////////
	// Step 5: retrieve the signature data
	////////////////////////////////////////////////////////////////////
	
	exchange_apdu("PROVE SIGNATURE A'", "802b0100", data, sw, 0x9000);
	mpz_class A_prime = data.mpz_val();
	
	exchange_apdu("PROVE SIGNATURE e^", "802b0200", data, sw, 0x9000);
	mpz_class e_hat = data.mpz_val();
	
	exchange_apdu("PROVE SIGNATURE v'^", "802b0300", data, sw, 0x9000);
	mpz_class v_prime_hat = data.mpz_val();
	
	////////////////////////////////////////////////////////////////////
	// Step 6: retrieve the attribute values
	////////////////////////////////////////////////////////////////////
	
	std::vector<mpz_class> a_i_hat;
	std::vector<silvia_attribute*> a_i;
	
	// Master secret
	exchange_apdu("GET RESPONSE", "802C0000", data, sw, 0x9000);
	a_i_hat.push_back(data.mpz_val());
	
	// Expiry
	exchange_apdu("GET RESPONSE", "802C0100", data, sw, 0x9000);
	silvia_string_attribute expiry;
	expiry.from_rep(data.mpz_val());
	a_i.push_back(&expiry);
	
	// Over 12
	exchange_apdu("GET RESPONSE", "802C0200", data, sw, 0x9000);
	a_i_hat.push_back(data.mpz_val());
	
	// Over 16
	exchange_apdu("GET RESPONSE", "802C0300", data, sw, 0x9000);
	a_i_hat.push_back(data.mpz_val());
	
	// Over 18
	exchange_apdu("GET RESPONSE", "802C0400", data, sw, 0x9000);
	silvia_string_attribute over18;
	over18.from_rep(data.mpz_val());
	a_i.push_back(&over18);
	
	// Over 21
	exchange_apdu("GET RESPONSE", "802C0500", data, sw, 0x9000);
	a_i_hat.push_back(data.mpz_val());
	
	// We have all the data, make a copy
	context_val = context.mpz_val();
	c_val = c;
	A_prime_val = A_prime;
	e_hat_val = e_hat;
	v_prime_hat_val = v_prime_hat;
	a_i_hat_val = a_i_hat;
	n1_value = n1;
	
	////////////////////////////////////////////////////////////////////
	// Step 7: verify the proof
	////////////////////////////////////////////////////////////////////
	
	// Proof specification
	std::vector<bool> D;
	D.push_back(true);		// expiry
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

bytestring fixLength(bytestring str, int length) {
	while (str.size() < length) str = "00" + str;
	return str;
}

int issue_credential() {
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
	silvia_pub_key *pub_key = &pubkey;

	mpz_class p("10436034022637868273483137633548989700482895839559909621411910579140541345632481969613724849214412062500244238926015929148144084368427474551770487566048119");
	mpz_class q("9204968012315139729618449685392284928468933831570080795536662422367142181432679739143882888540883909887054345986640656981843559062844656131133512640733759");
	
	silvia_priv_key privkey(p, q);
	silvia_priv_key *priv_key = &privkey;

	silvia_issuer issuer(pub_key, priv_key);

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
	bytestring bsid = "000a"; // age credential
	bytestring size = "0005";
	bytestring flags = "000000";
	bytestring timestamp = "01020304";
	
	context = fixLength(context, SYSPAR(l_H)/8);

	bytestring data;
	unsigned short sw;
	
	
	////////////////////////////////////////////////////////////////////
	// Step 2: log in
	////////////////////////////////////////////////////////////////////	
	
	exchange_apdu("SELECT", "00A404000849524D416361726400", data, sw, 0x9000);
	exchange_apdu("VERIFY PIN", "00200000083030303000000000", data, sw, 0x9000);
	exchange_apdu("VERIFY PIN", "00200001083030303030300000", data, sw, 0x9000);

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
	bytestring bsn(pub_key->get_n());
	bsn = fixLength(bsn, SYSPAR(l_n)/8);
	n_apdu.append_data(bsn);
	exchange_apdu("ISSUE PUBKEY(n)", n_apdu.get_apdu(), data, sw, 0x9000);

	silvia_apdu S_apdu(0x80, 0x11, 0x01, 0x00);
	bytestring bsS(pub_key->get_S());
	bsS = fixLength(bsS, SYSPAR(l_n)/8);
	S_apdu.append_data(bsS);
	exchange_apdu("ISSUE PUBKEY(S)", S_apdu.get_apdu(), data, sw, 0x9000);

	silvia_apdu Z_apdu(0x80, 0x11, 0x02, 0x00);
	bytestring bsZ(pub_key->get_Z());
	bsZ = fixLength(bsZ, SYSPAR(l_n)/8);
	Z_apdu.append_data(bsZ);
	exchange_apdu("ISSUE PUBKEY(Z)", Z_apdu.get_apdu(), data, sw, 0x9000);

	for (int i = 0; i < pub_key->get_R().size(); i++) {
		silvia_apdu R_apdu(0x80, 0x11, 0x03, i);
		bytestring bsR(pub_key->get_R()[i]);
		bsR = fixLength(bsR, SYSPAR(l_n)/8);
		R_apdu.append_data(bsR);
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
	int fail_count = 0;
	int ok_count = 0;
	
	std::vector<mpz_class> n1_vals;
	std::vector<mpz_class> context_vals;
	std::vector<mpz_class> c_vals;
	std::vector<mpz_class> A_prime_vals;
	std::vector<mpz_class> e_hat_vals;
	std::vector<mpz_class> v_prime_hat_vals;
	std::vector<std::vector<mpz_class> > a_i_hat_vals;
	
	size_t succ_max_n1_len = 0;
	size_t succ_min_n1_len = 65536;
	size_t fail_max_n1_len = 0;
	size_t fail_min_n1_len = 65536;
	
	size_t succ_max_context_len = 0;
	size_t succ_min_context_len = 65536;
	size_t fail_max_context_len = 0;
	size_t fail_min_context_len = 65536;
	
	size_t succ_max_c_len = 0;
	size_t succ_min_c_len = 65536;
	size_t fail_max_c_len = 0;
	size_t fail_min_c_len = 65536;
	
	size_t succ_max_A_prime_len = 0;
	size_t succ_min_A_prime_len = 65536;
	size_t fail_max_A_prime_len = 0;
	size_t fail_min_A_prime_len = 65536;
	
	size_t succ_max_e_hat_len = 0;
	size_t succ_min_e_hat_len = 65536;
	size_t fail_max_e_hat_len = 0;
	size_t fail_min_e_hat_len = 65536;
	
	size_t succ_max_v_prime_hat_len = 0;
	size_t succ_min_v_prime_hat_len = 65536;
	size_t fail_max_v_prime_hat_len = 0;
	size_t fail_min_v_prime_hat_len = 65536;
	
	size_t succ_max_a_i_hat_len = 0;
	size_t succ_min_a_i_hat_len = 65536;
	size_t fail_max_a_i_hat_len = 0;
	size_t fail_min_a_i_hat_len = 65536;
	
	issue_credential();

	for (int i = 0; i < 1000; i++)
	{
		mpz_class n1;
		mpz_class context;
		mpz_class c;
		mpz_class A_prime;
		mpz_class e_hat;
		mpz_class v_prime_hat;
		std::vector<mpz_class> a_i_hat;
		
		bool result = test_full_proof(n1, context, c, A_prime, e_hat, v_prime_hat, a_i_hat);
		
		size_t n1_size = mpz_sizeinbase(_Z(n1), 2);
		size_t context_size = mpz_sizeinbase(_Z(context), 2);
		size_t c_size = mpz_sizeinbase(_Z(c), 2);
		size_t A_prime_size = mpz_sizeinbase(_Z(A_prime), 2);
		size_t e_hat_size = mpz_sizeinbase(_Z(e_hat), 2);
		size_t v_prime_hat_size = mpz_sizeinbase(_Z(v_prime_hat), 2);
		size_t min_a_i_hat = 65536;
		size_t max_a_i_hat = 0;
		
		for (std::vector<mpz_class>::iterator ait = a_i_hat.begin(); ait != a_i_hat.end(); ait++)
		{
			size_t a_i_hat_size = mpz_sizeinbase(_Z((*ait)), 2);
			
			min_a_i_hat = (a_i_hat_size < min_a_i_hat) ? a_i_hat_size : min_a_i_hat;
			max_a_i_hat = (a_i_hat_size > max_a_i_hat) ? a_i_hat_size : max_a_i_hat;
		}
		
		if (result)
		{
			ok_count++;
			
			succ_max_n1_len = (n1_size > succ_max_n1_len) ? n1_size : succ_max_n1_len;
			succ_min_n1_len = (n1_size < succ_min_n1_len) ? n1_size : succ_min_n1_len;
			succ_max_context_len = (context_size > succ_max_context_len) ? context_size : succ_max_context_len;
			succ_min_context_len = (context_size < succ_min_context_len) ? context_size : succ_min_context_len;
			succ_max_c_len = (c_size > succ_max_c_len) ? c_size : succ_max_c_len;
			succ_min_c_len = (c_size < succ_min_c_len) ? c_size : succ_min_c_len;
			succ_max_A_prime_len = (A_prime_size > succ_max_A_prime_len) ? A_prime_size : succ_max_A_prime_len;
			succ_min_A_prime_len = (A_prime_size < succ_min_A_prime_len) ? A_prime_size : succ_min_A_prime_len;
			succ_max_e_hat_len = (e_hat_size > succ_max_e_hat_len) ? e_hat_size : succ_max_e_hat_len;
			succ_min_e_hat_len = (e_hat_size < succ_min_e_hat_len) ? e_hat_size : succ_min_e_hat_len;
			succ_max_v_prime_hat_len = (v_prime_hat_size > succ_max_v_prime_hat_len) ? v_prime_hat_size : succ_max_v_prime_hat_len;
			succ_min_v_prime_hat_len = (v_prime_hat_size < succ_min_v_prime_hat_len) ? v_prime_hat_size : succ_min_v_prime_hat_len;
			succ_max_a_i_hat_len = (max_a_i_hat > succ_max_a_i_hat_len) ? max_a_i_hat : succ_max_a_i_hat_len;
			succ_min_a_i_hat_len = (min_a_i_hat < succ_min_a_i_hat_len) ? min_a_i_hat : succ_min_a_i_hat_len;
		}
		else
		{
			fail_count++;
			
			n1_vals.push_back(n1);
			context_vals.push_back(context);
			c_vals.push_back(c);
			A_prime_vals.push_back(A_prime);
			e_hat_vals.push_back(e_hat);
			v_prime_hat_vals.push_back(v_prime_hat);
			a_i_hat_vals.push_back(a_i_hat);

			fail_max_n1_len = (n1_size > fail_max_n1_len) ? n1_size : fail_max_n1_len;
			fail_min_n1_len = (n1_size < fail_min_n1_len) ? n1_size : fail_min_n1_len;
			fail_max_context_len = (context_size > fail_max_context_len) ? context_size : fail_max_context_len;
			fail_min_context_len = (context_size < fail_min_context_len) ? context_size : fail_min_context_len;
			fail_max_c_len = (c_size > fail_max_c_len) ? c_size : fail_max_c_len;
			fail_min_c_len = (c_size < fail_min_c_len) ? c_size : fail_min_c_len;
			fail_max_A_prime_len = (A_prime_size > fail_max_A_prime_len) ? A_prime_size : fail_max_A_prime_len;
			fail_min_A_prime_len = (A_prime_size < fail_min_A_prime_len) ? A_prime_size : fail_min_A_prime_len;
			fail_max_e_hat_len = (e_hat_size > fail_max_e_hat_len) ? e_hat_size : fail_max_e_hat_len;
			fail_min_e_hat_len = (e_hat_size < fail_min_e_hat_len) ? e_hat_size : fail_min_e_hat_len;
			fail_max_v_prime_hat_len = (v_prime_hat_size > fail_max_v_prime_hat_len) ? v_prime_hat_size : fail_max_v_prime_hat_len;
			fail_min_v_prime_hat_len = (v_prime_hat_size < fail_min_v_prime_hat_len) ? v_prime_hat_size : fail_min_v_prime_hat_len;
			fail_max_a_i_hat_len = (max_a_i_hat > fail_max_a_i_hat_len) ? max_a_i_hat : fail_max_a_i_hat_len;
			fail_min_a_i_hat_len = (min_a_i_hat < fail_min_a_i_hat_len) ? min_a_i_hat : fail_min_a_i_hat_len;
			break;
		}
		
		printf("\nSuccesses: %d, failures %d\n", ok_count, fail_count);
	}
	
	printf("\n");
	
	for (int i = 0; i < fail_count; i++)
	{
		printf("Failure %d\n\n", i + 1);
		printf("n1      = "); printmpz(n1_vals[i]); printf("\n");
		printf("context = "); printmpz(context_vals[i]); printf("\n");
		printf("c       = "); printmpz(c_vals[i]); printf("\n");
		printf("A'      = "); printmpz(A_prime_vals[i]); printf("\n");
		printf("e^      = "); printmpz(e_hat_vals[i]); printf("\n");
		printf("v'^     = "); printmpz(v_prime_hat_vals[i]); printf("\n");
		
		int count = 0;
		
		for (std::vector<mpz_class>::iterator ait = a_i_hat_vals[i].begin(); ait != a_i_hat_vals[i].end(); ait++)
		{
			printf("a[%d]^   = ", count++); printmpz((*ait)); printf("\n");
		}
		
		printf("\n");
	}
	
	printf("\n");
	
	printf("Value        min(succ) max(succ) min(fail) max(fail)\n");
	printf("n1           %9zd %9zd %9zd %9zd\n", succ_min_n1_len, succ_max_n1_len, fail_min_n1_len, fail_max_n1_len);
	printf("context      %9zd %9zd %9zd %9zd\n", succ_min_context_len, succ_max_context_len, fail_min_context_len, fail_max_context_len);
	printf("c            %9zd %9zd %9zd %9zd\n", succ_min_c_len, succ_max_c_len, fail_min_c_len, fail_max_c_len);
	printf("A'           %9zd %9zd %9zd %9zd\n", succ_min_A_prime_len, succ_max_A_prime_len, fail_min_A_prime_len, fail_max_A_prime_len);
	printf("e^           %9zd %9zd %9zd %9zd\n", succ_min_e_hat_len, succ_max_e_hat_len, fail_min_e_hat_len, fail_max_e_hat_len);
	printf("v'^          %9zd %9zd %9zd %9zd\n", succ_min_v_prime_hat_len, succ_max_v_prime_hat_len, fail_min_v_prime_hat_len, fail_max_v_prime_hat_len);
	printf("a[i]^        %9zd %9zd %9zd %9zd\n", succ_min_a_i_hat_len, succ_max_a_i_hat_len, fail_min_a_i_hat_len, fail_max_a_i_hat_len);
	
	printf("\n");
	
	return 0;
}
	
