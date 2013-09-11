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
 silvia_verifier_spec.h

 Verifier specification
 *****************************************************************************/

#ifndef _SILVIA_VERIFIER_SPEC_H
#define _SILVIA_VERIFIER_SPEC_H

#include <gmpxx.h>
#include "silvia_types.h"
#include <vector>
#include <string>

/**
 * Verifier specification class
 */
 
class silvia_verifier_specification
{
public:
	/**
	 * Constructor
	 * @param verifier_name the verifier name
	 * @param short_msg what to display when using this verifier specification
	 * @param verifier_id the verifier ID
	 * @param credential_id the credential ID
	 * @param attribute_names the names of the attributes in the credential
	 * @param D the set describing which attributes to reveal
	 */
	silvia_verifier_specification
	(
		std::string verifier_name,
		std::string short_msg,
		unsigned int verifier_id,
		unsigned short credential_id,
		std::vector<std::string> attribute_names,
		std::vector<bool> D
	);
	
	/**
	 * Get the verifier name
	 * @return the verifier name
	 */
	std::string get_verifier_name();
	
	/**
	 * Get the short message to display for this verifier
	 * @return the short message to display for this verifier
	 */
	std::string get_short_msg();
	
	/**
	 * Get the verifier ID
	 * @return the verifier ID
	 */
	unsigned int get_verifier_id();
	
	/**
	 * Get the credential ID
	 * @return the credential ID
	 */
	unsigned short get_credential_id();
	
	/**
	 * Get the attribute names
	 * @return the attribute names
	 */
	std::vector<std::string>& get_attribute_names();
	
	/**
	 * Get the set describing which attributes to reveal
	 * @return the set describing which attributes to reveal
	 */
	std::vector<bool>& get_D();
	
private:
	std::string verifier_name;
	std::string short_msg;
	unsigned int verifier_id;
	unsigned short credential_id;
	std::vector<std::string> attribute_names;
	std::vector<bool> D;
};

#endif // !_SILVIA_VERIFIER_SPEC_H

