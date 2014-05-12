/* $Id$ */

/*
 * Copyright (c) 2014 Antonio de la Piedra
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
 silvia_irma_manager.h

 Credential manager for IRMA cards
 *****************************************************************************/

#ifndef _SILVIA_IRMA_MANAGER_H
#define _SILVIA_IRMA_MANAGER_H

#include <gmpxx.h>
#include <vector>
#include <utility>
#include <assert.h>
#include <string>
#include <iostream>
#include <sstream>
#include <ctime>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <signal.h>

/*
 * Card versions
 */
#define	IRMA_VERSION_0_8_X		8


/**
 * IRMA manager class
 */
 
class silvia_irma_manager
{
public:

	static const int LOG_SIZE = 30;
	static const int LOG_ENTRY_SIZE = 16;
	static const char LOG_ENTRIES_PER_APDU = 255 / 16;   

	/**
	 * Constructor
	 * @param pubkey the manager public key
	 * @param vspec the manager specification
	 */
	silvia_irma_manager();
	
	/**
	 * Destructor
	 */
	~silvia_irma_manager();
	
	/**
	 * Get the command sequence for reading the log of the IRMA card, with 
	 * PIN verification based on the specified PIN
	 * @param PIN the administration PIN
	 * @return the command sequence for reading the log of the IRMA card application
	 */
	std::vector<bytestring> get_log_commands(std::string PIN);

	/**
	 * Get the command sequence for deleting credentials, with 
	 * PIN verification based on the specified PIN
	 * @param credential the credential ID
	 * @param PIN the administration PIN
	 * @return the command sequence for deleting a certain credential stored
	 * in the IRMA card
	 */
	std::vector<bytestring> del_cred_commands(std::string credential, std::string PIN);

	/**
	 * Get the command sequence for updating the administration PIN of the IRMA
	 * card, with PIN verification based on the specified PIN
	 * @param old_pin the current administration PIN
	 * @param new_pin the new administration PIN
	 * @return the command sequence for updating the administration pin of the IRMA card
	 */
	std::vector<bytestring> update_admin_pin_commands(std::string old_pin, std::string new_pin);

	/**
	 * Get the command sequence for updating the credential PIN of the IRMA
	 * card, with PIN verification based on the specified PIN
	 * @param old_pin the current credential PIN
	 * @param new_pin the new credential PIN
	 * @return the command sequence for updating the credential pin of the IRMA card
	 */
	std::vector<bytestring> update_cred_pin_commands(std::string old_pin, std::string new_pin);

	/**
	 * Get the command sequence for listing the credentials stored in the IRMA card
	 * @param PIN the administration PIN
	 * @return the command sequence for listing the credentials stored in the IRMA card
	 */
	std::vector<bytestring> list_credentials_commands(std::string PIN);
	
};

#endif // !_SILVIA_IRMA_MANAGER_H

