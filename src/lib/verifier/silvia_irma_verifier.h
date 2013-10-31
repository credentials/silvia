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
 silvia_irma_verifier.h

 Credential proof verifier for IRMA cards
 *****************************************************************************/

#ifndef _SILVIA_IRMA_VERIFIER_H
#define _SILVIA_IRMA_VERIFIER_H

#include <gmpxx.h>
#include "silvia_types.h"
#include "silvia_verifier.h"
#include "silvia_bytestring.h"
#include "silvia_verifier_spec.h"
#include <vector>
#include <utility>

/*
 * Card versions
 */
#define IRMA_VERSION_0_7_X		7
#define	IRMA_VERSION_0_8_X		8

/**
 * IRMA verifier class
 */
 
class silvia_irma_verifier
{
public:
	/**
	 * Constructor
	 * @param pubkey the issuer public key
	 * @param vspec the verifier specification
	 */
	silvia_irma_verifier(silvia_pub_key* pubkey, silvia_verifier_specification* vspec);
	
	/**
	 * Destructor
	 */
	~silvia_irma_verifier();
	
	/**
	 * Get the select command sequence
	 * @return the command sequence for selecting the IRMA card application
	 */
	std::vector<bytestring> get_select_commands();
	
	/**
	 * Submit and verify the select command return values
	 * @return true if the IRMA application was selected successfully and is supported
	 */
	bool submit_select_data(std::vector<bytestring>& results);
	
	/**
	 * Get the command sequence for generating a proof
	 * @return the command sequence for generating a proof (empty if in the wrong state)
	 */
	std::vector<bytestring> get_proof_commands();
	
	/**
	 * Submit and verify the results from the card
	 * @param results the return data from the card
	 * @param revealed the revealed attributes as pairs of (id, value)
	 * @return true if the proof verified correctly, false otherwise
	 */
	bool submit_and_verify(std::vector<bytestring>& results, std::vector<std::pair<std::string, bytestring> >& revealed);
	
	/**
	 * Abort a verification (call if card processing fails); discards internal state
	 */
	void abort();

private:
	// Internal state
	silvia_pub_key* pubkey;
	silvia_verifier* verifier;
	silvia_verifier_specification* vspec;
	bytestring context;
	int irma_card_version;
	
	enum
	{
		IRMA_VERIFIER_START,
		IRMA_VERIFIER_WAIT_SELECT,
		IRMA_VERIFIER_SELECTED,
		IRMA_VERIFIER_WAIT_ANSWER
	}
	irma_verifier_state;
};

#endif // !_SILVIA_IRMA_VERIFIER_H

