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
 silvia_irma_issuer.h

 Credential issuer for IRMA cards
 *****************************************************************************/

#include "config.h"
#include <gmpxx.h>
#include "silvia_types.h"
#include "silvia_issuer.h"
#include "silvia_irma_issuer.h"
#include "silvia_apdu.h"
#include "silvia_rand.h"
#include "silvia_parameters.h"
#include <vector>
#include <assert.h>
#include <time.h>

#define MPZ_FROM_RESULT(result_index) results[result_index].substr(0, results[result_index].size() - 2).mpz_val()

#define PAD_TO_SYSPAR(b,syspar) while (b.size() < SYSPAR_BYTES(syspar)) b = "00" + b;

#define IRMA_CREDENTIAL_METADATA_VERSION	"01"

silvia_irma_issuer::silvia_irma_issuer(silvia_pub_key* pubkey, silvia_priv_key* privkey, silvia_issue_specification* ispec)
{
	assert(pubkey->get_R().size() >= (ispec->get_attributes().size() + 2));		// Check if we have enough R values to issue this credential
	
	this->pubkey = pubkey;
	this->privkey = privkey;
	this->ispec = ispec;
	
	irma_issuer_state = IRMA_ISSUER_START;
	
	issuer = new silvia_issuer(pubkey, privkey);
	
	metadata_attribute = NULL;
}

silvia_irma_issuer::~silvia_irma_issuer()
{
	if (metadata_attribute != NULL) delete metadata_attribute;
	metadata_attribute = NULL;
	
	delete issuer;
}

std::vector<bytestring> silvia_irma_issuer::get_select_commands(std::string PIN)
{
	assert(irma_issuer_state == IRMA_ISSUER_START);
	assert(PIN.size() <= 8);
	
	std::vector<bytestring> commands;
	
	////////////////////////////////////////////////////////////////////
	// Step 1: select application
	////////////////////////////////////////////////////////////////////
	
	commands.push_back("00A4040009F849524D416361726400");	// version >= 0.8
	
	////////////////////////////////////////////////////////////////////
	// Step 2: verify PIN
	////////////////////////////////////////////////////////////////////
	
	silvia_apdu verify_pin(0x00, 0x20, 0x00, 0x00);
	
	bytestring pin_data;
	pin_data.wipe(8);
	
	memcpy(&pin_data[0], PIN.c_str(), PIN.size());
	
	verify_pin.append_data(pin_data);
	
	commands.push_back(verify_pin.get_apdu());
	
	irma_issuer_state = IRMA_ISSUER_WAIT_SELECT;
	
	return commands;
}

bool silvia_irma_issuer::submit_select_data(std::vector<bytestring>& results)
{
	assert(irma_issuer_state == IRMA_ISSUER_WAIT_SELECT);
	
	// Check that the number of responses matches what we expect
	if (results.size() != 2)
	{
		this->abort();
		
		return false;
	}
	
	////////////////////////////////////////////////////////////////////
	// Check status words for all results
	////////////////////////////////////////////////////////////////////
	
	for (std::vector<bytestring>::iterator i = results.begin(); i != results.end(); i++)
	{
		if (i->substr(i->size() - 2) != "9000")
		{
			this->abort();
		
			return false;
		}
	}
	
	irma_issuer_state = IRMA_ISSUER_SELECTED;
	
	return true;
}

std::vector<bytestring> silvia_irma_issuer::get_issue_commands_round_1()
{
	assert(irma_issuer_state == IRMA_ISSUER_SELECTED);
	
	std::vector<bytestring> commands;
	
	////////////////////////////////////////////////////////////////////
	// Step 3: start issuance
	////////////////////////////////////////////////////////////////////
	
	// FIXME: context is randomly generated and kept as state!
	mpz_class context_mpz = silvia_rng::i()->get_random(SYSPAR(l_H));
	context = bytestring(context_mpz);
	bytestring id;
	id += (unsigned char) (ispec->get_credential_id() & 0xff00) >> 8;
	id += (unsigned char) (ispec->get_credential_id() & 0x00ff);
	
	bytestring attr_count;
	attr_count += (unsigned char) ((ispec->get_attributes().size() + 1) & 0xff00) >> 8; // +1 for expires
	attr_count += (unsigned char) ((ispec->get_attributes().size() + 1) & 0x00ff); 		// +1 for expires
	
	// FIXME: actually do something with these flags!
	bytestring attr_flags = "000000";
	
	bytestring timestamp = (unsigned long) time(NULL);
	timestamp = timestamp.substr(timestamp.size() - 4);
	
	PAD_TO_SYSPAR(context, l_H);
	
	silvia_apdu issue_start(0x80, 0x10, 0x00, 0x00);
	
	issue_start.append_data(id);
	issue_start.append_data(attr_count);
	issue_start.append_data(attr_flags);
	issue_start.append_data(context);
	issue_start.append_data(timestamp);
	
	commands.push_back(issue_start.get_apdu());
	
	////////////////////////////////////////////////////////////////////
	// Step 4: write the public key to the card
	////////////////////////////////////////////////////////////////////
	
	// n
	silvia_apdu issue_set_n(0x80, 0x11, 0x00, 0x00);
	bytestring n(pubkey->get_n());
	
	// Pad if necessary
	PAD_TO_SYSPAR(n, l_n);
	
	issue_set_n.append_data(n);
	
	commands.push_back(issue_set_n.get_apdu());
	
	// S
	silvia_apdu issue_set_S(0x80, 0x11, 0x01, 0x00);
	bytestring S(pubkey->get_S());
	
	// Pad if necessary
	PAD_TO_SYSPAR(S, l_n);
	
	issue_set_S.append_data(S);
	
	commands.push_back(issue_set_S.get_apdu());
	
	// Z
	silvia_apdu issue_set_Z(0x80, 0x11, 0x02, 0x00);
	bytestring Z(pubkey->get_Z());
	
	// Pad if necessary
	PAD_TO_SYSPAR(Z, l_n);
	
	issue_set_Z.append_data(Z);
	
	commands.push_back(issue_set_Z.get_apdu());
	
	for (int i = 0; i < (ispec->get_attributes().size() + 2); i++)
	{
		silvia_apdu issue_set_R(0x80, 0x11, 0x03, (unsigned char) (0x00 + i));
		
		bytestring R(pubkey->get_R()[i]);
		
		// Pad if necessary
		PAD_TO_SYSPAR(R, l_n);
		
		issue_set_R.append_data(R);
		
		commands.push_back(issue_set_R.get_apdu());
	}
	
	////////////////////////////////////////////////////////////////////
	// Step 5: write the attributes to the card
	////////////////////////////////////////////////////////////////////
	
	issue_attributes.clear();
	
	// Create the "expires+metadata" attribute
	bytestring expires_and_metadata;
	
	// Add metadata version number
	expires_and_metadata += IRMA_CREDENTIAL_METADATA_VERSION;
	
	// Add expiration date
	int expires = ispec->get_expires();
	
	expires_and_metadata += (unsigned char) ((expires & 0x00ff0000) >> 16);
	expires_and_metadata += (unsigned char) ((expires & 0x0000ff00) >> 8);
	expires_and_metadata += (unsigned char)  (expires & 0x000000ff);
	
	// Add credential ID
	expires_and_metadata += (unsigned char) (ispec->get_credential_id() & 0xff00) >> 8;
	expires_and_metadata += (unsigned char) (ispec->get_credential_id() & 0x00ff);
	
	metadata_attribute = new silvia_integer_attribute(expires_and_metadata.mpz_val());
	
	silvia_apdu write_expires_attr(0x80, 0x12, 0x01, 0x00);
	
	write_expires_attr.append_data(metadata_attribute->bs_rep());
	
	commands.push_back(write_expires_attr.get_apdu());
	
	issue_attributes.push_back(metadata_attribute);
	
	// Create all other attributes
	unsigned char ctr = 0x02;
	
	for (std::vector<silvia_attribute*>::iterator i = ispec->get_attributes().begin(); i != ispec->get_attributes().end(); i++, ctr++)
	{
		silvia_apdu write_attr(0x80, 0x12, ctr, 0x00);
		write_attr.append_data((*i)->bs_rep());
		
		commands.push_back(write_attr.get_apdu());
		
		issue_attributes.push_back(*i);
	}
	
	issuer->set_attributes(issue_attributes);
	
	////////////////////////////////////////////////////////////////////
	// Step 6: get issue commitment from card
	////////////////////////////////////////////////////////////////////
	
	silvia_apdu issue_commitment_nonce(0x80, 0x1a, 0x00, 0x00);
	
	bytestring n1(issuer->get_issuer_nonce());
	
	// pad if necessary
	PAD_TO_SYSPAR(n1, l_statzk);
	
	silvia_apdu issue_commitment(0x80, 0x1a, 0x00, 0x00);
	issue_commitment.append_data(n1);
	
	commands.push_back(issue_commitment.get_apdu());
	
	////////////////////////////////////////////////////////////////////
	// Step 7: get proof values c, v'^, s^
	////////////////////////////////////////////////////////////////////
	
	silvia_apdu get_proof_c(0x80, 0x1b, 0x01, 0x00);
	silvia_apdu get_proof_v_prime_hat(0x80, 0x1b, 0x02, 0x00);
	silvia_apdu get_proof_s_hat(0x80, 0x1b, 0x03, 0x00);
	
	commands.push_back(get_proof_c.get_apdu());
	commands.push_back(get_proof_v_prime_hat.get_apdu());
	commands.push_back(get_proof_s_hat.get_apdu());
	
	////////////////////////////////////////////////////////////////////
	// Step 8: get card nonce n2
	////////////////////////////////////////////////////////////////////
	
	silvia_apdu get_card_nonce_n2(0x80, 0x1c, 0x00, 0x00);
	
	commands.push_back(get_card_nonce_n2.get_apdu());
	
	irma_issuer_state = IRMA_ISSUER_WAIT_COMMITMENT;
	
	return commands;
}

bool silvia_irma_issuer::submit_issue_results_round_1(std::vector<bytestring>& results)
{
	assert(irma_issuer_state == IRMA_ISSUER_WAIT_COMMITMENT);
	
	// Check that the number of responses matches what we expect
	if (results.size() != 4 + ispec->get_attributes().size() + 2 + 1 + ispec->get_attributes().size() + 1 + 3 + 1)
	{
		this->abort();
		
		return false;
	}
	
	////////////////////////////////////////////////////////////////////
	// Check status words for all results
	////////////////////////////////////////////////////////////////////
	
	for (std::vector<bytestring>::iterator i = results.begin(); i != results.end(); i++)
	{
		if (i->substr(i->size() - 2) != "9000")
		{
			this->abort();
		
			return false;
		}
	}

	// Retrieve generic values from command results
	size_t r_index = 4 + ispec->get_attributes().size() + 2 + 1 + ispec->get_attributes().size();
	
	////////////////////////////////////////////////////////////////////
	// result[...]: U
	////////////////////////////////////////////////////////////////////
	
	mpz_class U = MPZ_FROM_RESULT(r_index);
	r_index++;
	
	////////////////////////////////////////////////////////////////////
	// result[...]: c
	////////////////////////////////////////////////////////////////////
	
	mpz_class c = MPZ_FROM_RESULT(r_index);
	r_index++;
	
	////////////////////////////////////////////////////////////////////
	// result[...]: v'^
	////////////////////////////////////////////////////////////////////
	
	mpz_class v_prime_hat = MPZ_FROM_RESULT(r_index);
	r_index++;
	
	////////////////////////////////////////////////////////////////////
	// result[...]: s^
	////////////////////////////////////////////////////////////////////
	
	mpz_class s_hat = MPZ_FROM_RESULT(r_index);
	r_index++;
	
	////////////////////////////////////////////////////////////////////
	// result[...]: n2
	////////////////////////////////////////////////////////////////////
	
	n2 = MPZ_FROM_RESULT(r_index);
	r_index++;
	
	////////////////////////////////////////////////////////////////////
	// Verify the card's commitment
	////////////////////////////////////////////////////////////////////
	
	if (!issuer->submit_and_verify_commitment(context.mpz_val(), U, c, v_prime_hat, s_hat))
	{
		this->abort();
		
		return false;
	}
	
	irma_issuer_state = IRMA_ISSUER_COMMITMENT_OK;
	
	return true;
}

std::vector<bytestring> silvia_irma_issuer::get_issue_commands_round_2()
{
	assert(irma_issuer_state == IRMA_ISSUER_COMMITMENT_OK);
	
	////////////////////////////////////////////////////////////////////
	// Compute the signature
	////////////////////////////////////////////////////////////////////
	
	mpz_class A;
	mpz_class e;
	mpz_class v_prime_prime;
	
	issuer->compute_signature(A, e, v_prime_prime);
	
	////////////////////////////////////////////////////////////////////
	// Create signature proof
	////////////////////////////////////////////////////////////////////
	
	mpz_class c;
	mpz_class e_hat;
	
	issuer->prove_signature(n2, context.mpz_val(), c, e_hat);
	
	std::vector<bytestring> commands;
	
	////////////////////////////////////////////////////////////////////
	// Step 9: write signature values A, e, v''
	////////////////////////////////////////////////////////////////////
	
	silvia_apdu issue_write_A(0x80, 0x1d, 0x01, 0x00);
	bytestring A_val(A);
	PAD_TO_SYSPAR(A_val, l_n);
	issue_write_A.append_data(A_val);
	commands.push_back(issue_write_A.get_apdu());
	
	silvia_apdu issue_write_e(0x80, 0x1d, 0x02, 0x00);
	bytestring e_val(e);
	PAD_TO_SYSPAR(e_val, l_e);
	issue_write_e.append_data(e_val);
	commands.push_back(issue_write_e.get_apdu());
	
	silvia_apdu issue_write_v_prime_prime(0x80, 0x1d, 0x03, 0x00);
	bytestring vpp_val(v_prime_prime);
	PAD_TO_SYSPAR(vpp_val, l_v);
	issue_write_v_prime_prime.append_data(vpp_val);
	commands.push_back(issue_write_v_prime_prime.get_apdu());
	
	////////////////////////////////////////////////////////////////////
	// Step 10: submit proof values c, e^
	////////////////////////////////////////////////////////////////////
	
	silvia_apdu issue_submit_proof_c(0x80, 0x1d, 0x04, 0x00);
	bytestring c_val(c);
	PAD_TO_SYSPAR(c_val, l_H);
	issue_submit_proof_c.append_data(c_val);
	commands.push_back(issue_submit_proof_c.get_apdu());
	
	silvia_apdu issue_submit_proof_e_hat(0x80, 0x1d, 0x05, 0x00);
	bytestring e_hat_val(e_hat);
	PAD_TO_SYSPAR(e_hat_val, l_n);
	issue_submit_proof_e_hat.append_data(e_hat_val);	
	commands.push_back(issue_submit_proof_e_hat.get_apdu());
	
	////////////////////////////////////////////////////////////////////
	// Step 11: verify signature
	////////////////////////////////////////////////////////////////////
	
	silvia_apdu verify_signature(0x80, 0x1f, 0x00, 0x00);
	
	commands.push_back(verify_signature.get_apdu());
	
	irma_issuer_state = IRMA_ISSUER_SIGN;
	
	return commands;
}

bool silvia_irma_issuer::submit_issue_results_round_2(std::vector<bytestring>& results)
{
	assert(irma_issuer_state == IRMA_ISSUER_SIGN);
	
	// Check that the number of responses matches what we expect
	if (results.size() != 6)
	{
		this->abort();
		
		return false;
	}
	
	////////////////////////////////////////////////////////////////////
	// Check status words for all results
	////////////////////////////////////////////////////////////////////
	
	for (std::vector<bytestring>::iterator i = results.begin(); i != results.end(); i++)
	{
		if (i->substr(i->size() - 2) != "9000")
		{
			this->abort();
		
			return false;
		}
	}
	
	issuer->reset();
	
	if (metadata_attribute != NULL) delete metadata_attribute;
	metadata_attribute = NULL;
	
	irma_issuer_state = IRMA_ISSUER_START;
	
	return true;
}

/**
 * Abort a verification (call if card processing fails); discards internal state
 */
void silvia_irma_issuer::abort()
{
	issuer->reset();
	
	if (metadata_attribute != NULL) delete metadata_attribute;
	metadata_attribute = NULL;
	
	irma_issuer_state = IRMA_ISSUER_START;
}
