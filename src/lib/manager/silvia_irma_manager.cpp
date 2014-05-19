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

#include "config.h"
#include <gmpxx.h>
#include "silvia_types.h"
#include "silvia_apdu.h"
#include "silvia_rand.h"
#include "silvia_parameters.h"
#include "silvia_irma_manager.h"
#include <vector>
#include <iomanip>
#include <ctime>
#include <assert.h>
#include <time.h>

silvia_irma_manager::silvia_irma_manager()
{
	/* XXXX: Not implemented! */
}

silvia_irma_manager::~silvia_irma_manager()
{
}

std::vector<bytestring> silvia_irma_manager::get_log_commands(std::string PIN)
{
	bool rv = true;

	std::vector<bytestring> commands;
	std::vector<bytestring> results;


	assert(PIN.size() <= 8);
	
	////////////////////////////////////////////////////////////////////
	// Step 1: select application
	////////////////////////////////////////////////////////////////////
	
	commands.push_back("00A4040009F849524D416361726400");	// version >= 0.8
	
	////////////////////////////////////////////////////////////////////
	// Step 2: verify PIN
	////////////////////////////////////////////////////////////////////
	
	silvia_apdu verify_pin(0x00, 0x20, 0x00, 0x01);
	
	bytestring pin_data;
	pin_data.wipe(8);
	
	memcpy(&pin_data[0], PIN.c_str(), PIN.size());
	
	verify_pin.append_data(pin_data);
	
	commands.push_back(verify_pin.get_apdu());

	////////////////////////////////////////////////////////////////////
	// Step 3: Get log entries
	////////////////////////////////////////////////////////////////////
			
	for (char start_entry = 0x00; start_entry < LOG_SIZE; start_entry = (char)(start_entry + LOG_ENTRIES_PER_APDU))
	{
		silvia_apdu get_log_apdu(0x80, 0x3b, start_entry, 0x00);
		commands.push_back(get_log_apdu.get_apdu());
	}
	
	return commands;
}

std::vector<bytestring> silvia_irma_manager::del_cred_commands(std::string credential, std::string PIN)
{
	bool rv = true;

	std::vector<bytestring> commands;
	std::vector<bytestring> results;

	assert(PIN.size() <= 8);
	//assert(credential.size() == 2);
	
	////////////////////////////////////////////////////////////////////
	// Step 1: select application
	////////////////////////////////////////////////////////////////////
	
	commands.push_back("00A4040009F849524D416361726400");	// version >= 0.8
	
	////////////////////////////////////////////////////////////////////
	// Step 2: verify PIN
	////////////////////////////////////////////////////////////////////
	
	silvia_apdu verify_pin(0x00, 0x20, 0x00, 0x01);
	
	bytestring pin_data;
	pin_data.wipe(8);
	
	memcpy(&pin_data[0], PIN.c_str(), PIN.size());
	
	verify_pin.append_data(pin_data);
	
	commands.push_back(verify_pin.get_apdu());

	////////////////////////////////////////////////////////////////////
	// Step 3: select credential
	////////////////////////////////////////////////////////////////////

	std::stringstream ss;

	ss << std::setfill ('0') << std::setw(4) << std::hex << atoi(credential.c_str());
        std::string cmd = std::string("8030000002") + ss.str();               
	commands.push_back(cmd.c_str());

	ss.str("");
	ss.clear(); 

	////////////////////////////////////////////////////////////////////
	// Step 4: delete credential
	////////////////////////////////////////////////////////////////////

	ss << std::setfill ('0') << std::setw(4) << std::hex << std::time(0); //timestamp
        std::string cmd_del = std::string("8031000004") + ss.str();               

	commands.push_back(cmd_del.c_str());
	
	return commands;
}

std::vector<bytestring> silvia_irma_manager::update_admin_pin_commands(std::string old_pin, std::string new_pin)
{

	bool rv = true;

	std::vector<bytestring> commands;
	std::vector<bytestring> results;

	assert(old_pin.size() <= 8);
	assert(new_pin.size() <= 8);
	
	////////////////////////////////////////////////////////////////////
	// Step 1: select application
	////////////////////////////////////////////////////////////////////
	
	commands.push_back("00A4040009F849524D416361726400");	// version >= 0.8
	
	////////////////////////////////////////////////////////////////////
	// Step 2: update admin PIN
	////////////////////////////////////////////////////////////////////
	
	silvia_apdu verify_pin(0x00, 0x24, 0x00, 0x01);
	
	bytestring old_pin_data, new_pin_data;
	old_pin_data.wipe(8);
	new_pin_data.wipe(8);
	
	memcpy(&old_pin_data[0], old_pin.c_str(), old_pin.size());
	memcpy(&new_pin_data[0], new_pin.c_str(), new_pin.size());
	
	verify_pin.append_data(old_pin_data);
	verify_pin.append_data(new_pin_data);
	
	commands.push_back(verify_pin.get_apdu());

	return commands;
}

std::vector<bytestring> silvia_irma_manager::update_cred_pin_commands(std::string admin_pin, std::string new_pin)
{
	bool rv = true;

	std::vector<bytestring> commands;
	std::vector<bytestring> results;

	assert(admin_pin.size() <= 8);
	assert(new_pin.size() <= 8);
	
	////////////////////////////////////////////////////////////////////
	// Step 1: select application
	////////////////////////////////////////////////////////////////////
	
	commands.push_back("00A4040009F849524D416361726400");	// version >= 0.8
	
	////////////////////////////////////////////////////////////////////
	// Step 2: verify admin_pin
	////////////////////////////////////////////////////////////////////
	
	silvia_apdu verify_pin(0x00, 0x20, 0x00, 0x01);
	
	bytestring pin_data;
	pin_data.wipe(8);
	
	memcpy(&pin_data[0], admin_pin.c_str(), admin_pin.size());
	
	verify_pin.append_data(pin_data);
	
	commands.push_back(verify_pin.get_apdu());

	////////////////////////////////////////////////////////////////////
	// Step 3: update credential pin
	////////////////////////////////////////////////////////////////////

	silvia_apdu update_cred_pin(0x00, 0x24, 0x00, 0x00);
	
	bytestring cred_pin_data;
	cred_pin_data.wipe(8);
	
	memcpy(&cred_pin_data[0], new_pin.c_str(), new_pin.size());	
	update_cred_pin.append_data(cred_pin_data);
	
	commands.push_back(update_cred_pin.get_apdu());
	
	return commands;
}

std::vector<bytestring> silvia_irma_manager::list_credentials_commands(std::string PIN)
{
	bool rv = true;

	std::vector<bytestring> commands;
	std::vector<bytestring> results;

	assert(PIN.size() <= 8);
	
	////////////////////////////////////////////////////////////////////
	// Step 1: select application
	////////////////////////////////////////////////////////////////////
	
	commands.push_back("00A4040009F849524D416361726400");	// version >= 0.8
	
	////////////////////////////////////////////////////////////////////
	// Step 2: verify PIN
	////////////////////////////////////////////////////////////////////
	
	silvia_apdu verify_pin(0x00, 0x20, 0x00, 0x01);
	
	bytestring pin_data;
	pin_data.wipe(8);
	
	memcpy(&pin_data[0], PIN.c_str(), PIN.size());
	
	verify_pin.append_data(pin_data);
	
	commands.push_back(verify_pin.get_apdu());

	////////////////////////////////////////////////////////////////////
	// Step 3: get credentials
	////////////////////////////////////////////////////////////////////

	silvia_apdu list_credentials(0x80, 0x3A, 0x00, 0x00);
	
	commands.push_back(list_credentials.get_apdu());
	
	return commands;
}
