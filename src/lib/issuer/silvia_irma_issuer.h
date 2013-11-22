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

#ifndef _SILVIA_IRMA_ISSUER_H
#define _SILVIA_IRMA_ISSUER_H

#include <gmpxx.h>
#include "silvia_types.h"
#include "silvia_issuer.h"
#include "silvia_bytestring.h"
#include "silvia_issue_spec.h"
#include <vector>
#include <utility>

/*
 * Card versions
 */
#define	IRMA_VERSION_0_8_X		8

/**
 * IRMA issuer class
 */
 
class silvia_irma_issuer
{
public:
	/**
	 * Constructor
	 * @param pubkey the issuer public key
	 * @param vspec the issuer specification
	 */
	silvia_irma_issuer(silvia_pub_key* pubkey, silvia_priv_key* privkey, silvia_issue_specification* ispec);
	
	/**
	 * Destructor
	 */
	~silvia_irma_issuer();
	
	/**
	 * Get the select command sequence, with PIN verification based on the specified PIN
	 * @param PIN the user PIN
	 * @return the command sequence for selecting the IRMA card application
	 */
	std::vector<bytestring> get_select_commands(std::string PIN);
	
	/**
	 * Submit and verify the select command return values
	 * @return true if the IRMA application was selected successfully and is supported
	 */
	bool submit_select_data(std::vector<bytestring>& results);
	
	/**
	 * Get the command sequence for:
	 * - Starting issuance
	 * - Setting the public key
	 * - Writing the attributes
	 * - Retrieving the commitment
	 * - Retrieving the card nonce
	 * @return the command sequence for round 1 of issuance
	 */
	std::vector<bytestring> get_issue_commands_round_1();
	
	/**
	 * Submit the results from issuing round 1
	 * @param results the return data from the card
	 * @return true if the commitment verified correctly, false otherwise
	 */
	bool submit_issue_results_round_1(std::vector<bytestring>& results);
	
	/**
	 * Get the command sequence for:
	 * - Writing the signature
	 * - Verifying the signature
	 * @return the command sequence for round 2 of issuance
	 */
	std::vector<bytestring> get_issue_commands_round_2();
	
	/**
	 * Submit the results from issuing round 2
	 * @param results the return data from the card
	 * @return true if the issuance completed successfully, false otherwise
	 */
	bool submit_issue_results_round_2(std::vector<bytestring>& results);
	
	/**
	 * Abort issuance (call if card processing fails); discards internal state
	 */
	void abort();

private:
	// Internal state
	silvia_pub_key* pubkey;
	silvia_priv_key* privkey;
	silvia_issuer* issuer;
	silvia_issue_specification* ispec;
	bytestring context;
	int irma_card_version;
	silvia_integer_attribute* metadata_attribute;
	mpz_class n2;
	std::vector<silvia_attribute*> issue_attributes;
	
	enum
	{
		IRMA_ISSUER_START,
		IRMA_ISSUER_WAIT_SELECT,
		IRMA_ISSUER_SELECTED,
		IRMA_ISSUER_WAIT_COMMITMENT,
		IRMA_ISSUER_COMMITMENT_OK,
		IRMA_ISSUER_SIGN
	}
	irma_issuer_state;
};

#endif // !_SILVIA_IRMA_ISSUER_H

