/* $Id: silvia_verifier.cpp 55 2013-07-04 14:19:14Z rijswijk $ */

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
 silvia_irma_verifier.h

 Credential proof verifier for IRMA cards
 *****************************************************************************/

#include "config.h"
#include <gmpxx.h>
#include "silvia_types.h"
#include "silvia_verifier.h"
#include "silvia_irma_verifier.h"
#include "silvia_apdu.h"
#include "silvia_rand.h"
#include "silvia_parameters.h"
#include <vector>
#include <assert.h>
#include <time.h>

silvia_irma_verifier::silvia_irma_verifier(silvia_pub_key* pubkey, silvia_verifier_specification* vspec)
{
	this->pubkey = pubkey;
	this->vspec = vspec;
	
	irma_verifier_state = IRMA_VERIFIER_START;
	
	verifier = new silvia_verifier(pubkey);
}

silvia_irma_verifier::~silvia_irma_verifier()
{
	delete verifier;
}

std::vector<bytestring> silvia_irma_verifier::get_select_commands()
{
	assert(irma_verifier_state == IRMA_VERIFIER_START);
	
	std::vector<bytestring> commands;
	
	////////////////////////////////////////////////////////////////////
	// Step 1: select application
	////////////////////////////////////////////////////////////////////
	
	commands.push_back("00A404000849524D416361726400");		// version < 0.8
	commands.push_back("00A4040009F849524D416361726400");	// version >= 0.8
	
	irma_verifier_state = IRMA_VERIFIER_WAIT_SELECT;
	
	return commands;
}

bool silvia_irma_verifier::submit_select_data(std::vector<bytestring>& results)
{
	assert(irma_verifier_state == IRMA_VERIFIER_WAIT_SELECT);
	
	// Check that the number of responses matches what we expect
	if (results.size() != 2)
	{
		irma_verifier_state = IRMA_VERIFIER_START;
		
		verifier->reset();
		
		return false;
	}
	
	////////////////////////////////////////////////////////////////////
	// Check status words for all results
	////////////////////////////////////////////////////////////////////
	
	for (std::vector<bytestring>::iterator i = results.begin(); i != results.end(); i++)
	{
		if ((i->substr(i->size() - 2) != "9000") && 
		    (i->substr(i->size() - 2) != "6A82") &&
		    (i->substr(i->size() - 2) != "6D00"))
		{
			irma_verifier_state = IRMA_VERIFIER_START;
		
			verifier->reset();
		
			return false;
		}
	}
	
	////////////////////////////////////////////////////////////////////
	// Check IRMA card application version
	////////////////////////////////////////////////////////////////////
	
	// FIXME: actually parse this data rather than assuming the version
	//        number based on the length of the data
	bytestring irma_version_info;
	
	for (std::vector<bytestring>::iterator i = results.begin(); i != results.end(); i++)
	{
		if (i->substr(i->size() - 2) == "9000")
		{
			irma_version_info = i->substr(0, i->size() - 2);
			
			break;
		}
	}
	
	if (irma_version_info.size() == 0)
	{
		return false;	// No data?!
	}
	else if (irma_version_info.size() == 4)
	{
		irma_card_version = IRMA_VERSION_0_7_X;
	}
	else
	{
		irma_card_version = IRMA_VERSION_0_8_X;
	}
	
	irma_verifier_state = IRMA_VERIFIER_SELECTED;
	
	return true;
}

std::vector<bytestring> silvia_irma_verifier::get_proof_commands()
{
	assert(irma_verifier_state == IRMA_VERIFIER_SELECTED);
	
	std::vector<bytestring> commands;
	
	////////////////////////////////////////////////////////////////////
	// Step 2: start proof
	////////////////////////////////////////////////////////////////////
	
	// FIXME: context is randomly generated and kept as state!
	mpz_class context_mpz = silvia_rng::i()->get_random(SYSPAR(l_H));
	context = bytestring(context_mpz);
	bytestring id;
	id += (unsigned char) (vspec->get_credential_id() & 0xff00) >> 8;
	id += (unsigned char) (vspec->get_credential_id() & 0x00ff);
	
	// Build proof specification
	unsigned short D_val = 0;
	unsigned short D_mask = 0x02; // take into account that we never reveal the master secret
	
	for (std::vector<bool>::iterator i = vspec->get_D().begin(); i != vspec->get_D().end(); i++)
	{
		if ((*i) == true)
		{
			D_val += D_mask;
		}
		
		D_mask = D_mask << 1;
	}
	
	bytestring D = (unsigned long) D_val;
	D = D.substr(D.size() - 2);
	
	bytestring timestamp = (unsigned long) time(NULL);
	timestamp = timestamp.substr(timestamp.size() - 4);
	
	while (context.size() < (SYSPAR(l_H)/8)) context = "00" + context;
	
	silvia_apdu prove_apdu(0x80, 0x20, 0x00, 0x00);
	
	if (irma_card_version <= IRMA_VERSION_0_7_X)
	{
		prove_apdu.append_data(id);
		prove_apdu.append_data(context);
		prove_apdu.append_data(D);
		prove_apdu.append_data(timestamp);
	}
	else if (irma_card_version <= IRMA_VERSION_0_8_X)
	{
		/* Ordering changed from 0.7.x to 0.8.x */
		prove_apdu.append_data(id);
		prove_apdu.append_data(D);
		prove_apdu.append_data(context);
		prove_apdu.append_data(timestamp);
	}
	else
	{
		// NOT IMPLEMENTED!
		assert(false);
	}
	
	commands.push_back(prove_apdu.get_apdu());
	
	////////////////////////////////////////////////////////////////////
	// Step 3: send nonce and get commitment hash
	////////////////////////////////////////////////////////////////////
	
	mpz_class n1 = verifier->get_verifier_nonce();
	bytestring n1_val(n1);
	
	while (n1_val.size() < 10) n1_val = "00" + n1_val;
	
	silvia_apdu commit_apdu(0x80, 0x2a, 0x00, 0x00);
	commit_apdu.append_data(n1_val);
	
	commands.push_back(commit_apdu.get_apdu());
	
	////////////////////////////////////////////////////////////////////
	// Step 4: retrieve the signature data
	////////////////////////////////////////////////////////////////////
	
	// Prove signature A'
	commands.push_back("802b0100");
	
	// Prove signature e^
	commands.push_back("802b0200");
	
	// Prove signature v'^
	commands.push_back("802b0300");
	
	////////////////////////////////////////////////////////////////////
	// Step 5: retrieve the attribute values
	////////////////////////////////////////////////////////////////////
	
	for (unsigned char i = 0; i < (vspec->get_D().size() + 1); i++)
	{
		silvia_apdu get_response_apdu(0x80, 0x2C, i, 0x00);
		
		commands.push_back(get_response_apdu.get_apdu());
	}
	
	irma_verifier_state = IRMA_VERIFIER_WAIT_ANSWER;
	
	return commands;
}

/**
 * Submit and verify the results from the card
 * @param results the return data from the card
 * @param revealed the revealed attributes as pairs of (id, value)
 * @return true if the proof verified correctly, false otherwise
 */
bool silvia_irma_verifier::submit_and_verify(std::vector<bytestring>& results, std::vector<std::pair<std::string, bytestring> >& revealed)
{
	assert(irma_verifier_state == IRMA_VERIFIER_WAIT_ANSWER);
	
	// Check that the number of responses matches what we expect
	if (results.size() != 5 + vspec->get_D().size() + 1)
	{
		irma_verifier_state = IRMA_VERIFIER_START;
		
		verifier->reset();
		
		return false;
	}
	
	////////////////////////////////////////////////////////////////////
	// Check status words for all results
	////////////////////////////////////////////////////////////////////
	
	for (std::vector<bytestring>::iterator i = results.begin(); i != results.end(); i++)
	{
		if (i->substr(i->size() - 2) != "9000")
		{
			irma_verifier_state = IRMA_VERIFIER_START;
		
			verifier->reset();
		
			return false;
		}
	}
	
#define MPZ_FROM_RESULT(result_index) results[result_index].substr(0, results[result_index].size() - 2).mpz_val()

	// Retrieve generic values from command results
	
	////////////////////////////////////////////////////////////////////
	// result[1]: c
	////////////////////////////////////////////////////////////////////
	
	mpz_class c = MPZ_FROM_RESULT(1);
	
	////////////////////////////////////////////////////////////////////
	// result[2]: A'
	////////////////////////////////////////////////////////////////////
	
	mpz_class A_prime = MPZ_FROM_RESULT(2);
	
	////////////////////////////////////////////////////////////////////
	// result[3]: e^
	////////////////////////////////////////////////////////////////////
	
	mpz_class e_hat = MPZ_FROM_RESULT(3);
	
	////////////////////////////////////////////////////////////////////
	// result[4]: v'^
	////////////////////////////////////////////////////////////////////
	
	mpz_class v_prime_hat = MPZ_FROM_RESULT(4);
	
	// Retrieve hidden master secret and hidden and revealed attributes
	
	std::vector<mpz_class> a_i_hat;
	std::vector<silvia_attribute*> a_i;
	
	////////////////////////////////////////////////////////////////////
	// result[5]: s^ (aka a[0]^)
	////////////////////////////////////////////////////////////////////
	
	mpz_class s_hat = MPZ_FROM_RESULT(5);
	
	a_i_hat.push_back(s_hat);
	
	////////////////////////////////////////////////////////////////////
	// results[6-...] hidden and revealed attributes
	////////////////////////////////////////////////////////////////////
	
	size_t ri = 6;
	size_t ai = 0;
	
	for (std::vector<bool>::iterator i = vspec->get_D().begin(); i != vspec->get_D().end(); i++, ri++, ai++)
	{
		if (*i == true)
		{
			a_i.push_back(new silvia_integer_attribute(MPZ_FROM_RESULT(ri)));
			
			revealed.push_back(make_pair(vspec->get_attribute_names()[ai], results[ri].substr(0, results[ri].size() - 2)));
		}
		else
		{
			a_i_hat.push_back(MPZ_FROM_RESULT(ri));
		}
	}
	
	////////////////////////////////////////////////////////////////////
	// Finally, verify the result
	////////////////////////////////////////////////////////////////////
	
	irma_verifier_state = IRMA_VERIFIER_START;
	
	bool rv = verifier->verify(vspec->get_D(), context.mpz_val(), c, A_prime, e_hat, v_prime_hat, a_i_hat, a_i);
	
	for (std::vector<silvia_attribute*>::iterator i = a_i.begin(); i != a_i.end(); i++)
	{
		delete *i;
	}
	
	return rv;
}

/**
 * Abort a verification (call if card processing fails); discards internal state
 */
void silvia_irma_verifier::abort()
{
	verifier->reset();
	
	irma_verifier_state = IRMA_VERIFIER_START;
}
