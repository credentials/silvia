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
 silvia_issuescript.h

 XML reader that will read and parse Silvia issuing scripts
 *****************************************************************************/

#ifndef _SILVIA_ISSUESCRIPT_H
#define _SILVIA_ISSUESCRIPT_H

#include <gmpxx.h>
#include "silvia_types.h"
#include <vector>
#include <memory>

/**
 * Silvia issue script XML reader class
 */
class silvia_issuescript
{
public:
	/**
	 * Constructor
	 * @param file_name the file name of the issuing script to read
	 */
	silvia_issuescript(const std::string file_name);

	/**
	 * Is the object valid?
	 * @return true if the XML file was parsed successfully
	 */
	bool valid();

	/**
	 * Get the description of the issuing script
	 * @return the description of the issuing script
	 */
	std::string& get_description();

	/**
	 * Get the user PIN
	 * @return the user PIN
	 */
	std::string& get_user_PIN();

	/**
	 * Get the list of issue specifications
	 * @return the list of issue specifications
	 */
	std::vector<std::string>& get_issue_specs();

	/**
	 * Get the list of issuer public key files
	 * @return the list of issuer public key files
	 */
	std::vector<std::string>& get_issuer_ipks();

	/**
	 * Get the list of issuer private key files
	 * @return the list of issuer private key files
	 */
	std::vector<std::string>& get_issuer_isks();
	
private:
	bool is_valid;
	std::string description;
	std::string userPIN;
	std::vector<std::string> issue_specs;
	std::vector<std::string> issuer_ipks;
	std::vector<std::string> issuer_isks;
};

#endif // !_SILVIA_ISSUESCRIPT_H

