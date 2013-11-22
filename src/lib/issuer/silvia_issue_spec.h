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
 silvia_issue_spec.h

 Issuing specification for a specific credential
 *****************************************************************************/

#ifndef _SILVIA_ISSUE_SPEC_H
#define _SILVIA_ISSUE_SPEC_H

#include <gmpxx.h>
#include "silvia_types.h"
#include <vector>
#include <string>

/**
 * Credential issue specification class
 */
 
class silvia_issue_specification
{
public:
	/**
	 * Constructor -- note: this object will take ownership of
	 * the attributes specified to the constructor and will destruct
	 * them upon object destruction.
	 * @param credential_name the credential name
	 * @param issuer_name the issuer name
	 * @param credential_id the credential ID
	 * @param expires the expiry date
	 * @param attributes the attributes
	 */
	silvia_issue_specification
	(
		std::string credential_name,
		std::string issuer_name,
		unsigned short credential_id,
		int expires,
		std::vector<silvia_attribute*> attributes
	);

	/**
	 * Destructor
	 */
	~silvia_issue_specification();
	
	/**
	 * Get the credential name
	 * @return the credential name
	 */
	std::string get_credential_name();

	/**
	 * Get the issuer name
	 * @return the issuer name
	 */
	std::string get_issuer_name();

	/**
	 * Get the credential ID
	 * @return the credential ID
	 */
	unsigned short get_credential_id();

	/**
	 * Get the credential expiry date
	 * @return the credential expiry date
	 */
	int get_expires();

	/**
	 * Get the credential attributes. Note: it is not safe
	 * to keep using the attributes after the silvia_issue_specification
	 * object is destroyed.
	 * @return the attributes
	 */
	std::vector<silvia_attribute*>& get_attributes();
	
private:
	std::string credential_name;
	std::string issuer_name;
	unsigned short credential_id;
	int expires;
	std::vector<silvia_attribute*> attributes;
};

#endif // !_SILVIA_ISSUE_SPEC_H

