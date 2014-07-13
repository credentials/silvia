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
 silvia_manager.cpp

 Command-line management utility
 *****************************************************************************/

#include "config.h"
#include "silvia_parameters.h"
#include "silvia_apdu.h"
#ifdef WITH_PCSC
#include "silvia_pcsc_card.h"
#endif // WITH_PCSC
#ifdef WITH_NFC
#include "silvia_nfc_card.h"
#endif // WITH_NFC
#include "silvia_card_channel.h"
#include "silvia_irma_xmlreader.h"
#include "silvia_irma_manager.h"
#include "silvia_idemix_xmlreader.h"
#include "silvia_types.h"
#include <assert.h>
#include <string>
#include <iostream>
#include <sstream>
#include <ctime>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <signal.h>

static bool debug_output = false;

#define DEBUG_MSG(...)	{ if (debug_output) printf(__VA_ARGS__); }

#define MANAGER_OPT_LOG 0x00
#define MANAGER_OPT_CRED 0x01
#define MANAGER_OPT_UPDATE_ADMIN 0x02
#define MANAGER_OPT_DEL_CRED 0x03
#define MANAGER_OPT_UPDATE_CRED 0x04
#define MANAGER_OPT_READ_CRED 0x05

#define IRMA_VERIFIER_METADATA_OFFSET				(32 - 6)

/* Log entries */

const int IDX_TIMESTAMP = 0;
const int SIZE_TIMESTAMP = 4;
const int IDX_TERMINAL = 4;
const int SIZE_TERMINAL = 4;
const int IDX_ACTION = 8;
const int IDX_CREDENTIAL = 9;  
const int IDX_SELECTION = 11;

const char ACTION_NONE = '0';
const char ACTION_ISSUE = '1';
const char ACTION_PROVE = '2';
const char ACTION_REMOVE = '3';

void print_timestamp_log(std::string msg, std::string timestamp)
{
	time_t tstamp_int;
	std::stringstream tstamp_ss;

	tstamp_ss << std::hex << timestamp.c_str();
	tstamp_ss >> tstamp_int;
	
	printf("%s: %s\n", msg.c_str(), ctime(&tstamp_int));
}

void print_timestamp_irma(std::string msg, bytestring timestamp)
{
	time_t expires;
									
	if (timestamp[IRMA_VERIFIER_METADATA_OFFSET] != 0x00)
	{
		// Check metadata version number
		if (timestamp[IRMA_VERIFIER_METADATA_OFFSET] != 0x01)
		{
			printf("Invalid metadata attribute found!\n");
		}
		else
		{
			// Reconstruct expiry data from metadata
			expires = 0;
			expires += timestamp[IRMA_VERIFIER_METADATA_OFFSET + 1] << 16;
			expires += timestamp[IRMA_VERIFIER_METADATA_OFFSET + 2] << 8;
			expires += timestamp[IRMA_VERIFIER_METADATA_OFFSET + 3];
			expires *= 86400; // convert days to seconds
		}
	}
	else
	{
		// This is old style
		expires = (timestamp[timestamp.size() - 2] << 8) + (timestamp[timestamp.size() - 1]);
		expires *= 86400; // convert days to seconds
	}

	printf("%s: %s\n", msg.c_str(), ctime(&expires));
}

/* 
   print_log_entry is based on IdemixLogEntry
   by Wouter Lueks, Radboud University Nijmegen, March 2013.
*/

void print_log_entry(int n, std::string e) 
{
	std::vector<char> array(e.begin(), e.end());

	printf("Entry %d: ", n);

	char action = array[IDX_ACTION*2 + 1];

	switch(action) 
	{
		case ACTION_PROVE:
			printf("VERIFICATION\n");
			break;
		case ACTION_ISSUE:
			printf("ISSUANCE\n");
			break;
		case ACTION_REMOVE:
			printf("REMOVE\n");
			break;
		case ACTION_NONE:
                        printf("-- EMPTY ENTRY --\n");
			break;
		default:
			break;	
	}

	std::string timestamp = e.substr(IDX_TIMESTAMP, SIZE_TIMESTAMP*2);
	std::string credential = e.substr(IDX_CREDENTIAL*2, 4);
	std::string mask = e.substr(IDX_SELECTION*2, 4);

	std::stringstream cred_ss;

	unsigned int cred_int;   

	cred_ss << std::hex << credential;
	cred_ss >> cred_int;

	if (array[IDX_ACTION*2 + 1] == ACTION_PROVE)
		printf("Policy: %s\n", mask.c_str());	

	if (array[IDX_ACTION*2 + 1] != ACTION_NONE) {
		printf("Credential: %d\n", cred_int);
		print_timestamp_log("Timestamp", timestamp);
	}
}
            
void signal_handler(int signal)
{
	// Exit on any signal we receive and handle
	fprintf(stderr, "\nCaught signal, exiting...\n");
	
	exit(0);
}

void version(void)
{
	printf("The Simple Library for Verifying and Issuing Attributes (silvia)\n");
	printf("\n");
	printf("Command-line issuing utility for IRMA cards %s\n", VERSION);
	printf("\n");
	printf("Copyright (c) 2013 Roland van Rijswijk-Deij\n\n");
	printf("Use, modification and redistribution of this software is subject to the terms\n");
	printf("of the license agreement. This software is licensed under a 2-clause BSD-style\n");
	printf("license a copy of which is included as the file LICENSE in the distribution.\n");
}

void usage(void)
{
	printf("Silvia command-line IRMA manager %s\n\n", VERSION);
	printf("Usage:\n");
	printf("\tsilvia_manager [-lracso] [<credential>]");
#if defined(WITH_PCSC) && defined(WITH_NFC)
	printf(" [-P] [-N]");
#endif // WITH_PCSC && WITH_NFC
	printf("\n");
	printf("\tsilvia_manager -l Read the log of the IRMA card\n");
	printf("\tsilvia_manager -r <credential> Remove a credential stored in the card\n");
	printf("\tsilvia_manager -a Update admin pin\n");
	printf("\tsilvia_manager -c Update credential pin\n");
	printf("\tsilvia_manager -s List the credentials stored in the IRMA card\n");
	printf("\tsilvia_manager -o <credential> Read all the attributes of <credential>\n");
	printf("\n");
#if defined(WITH_PCSC) && defined(WITH_NFC)
	printf("\t-P                  Use PC/SC for card communication (default)\n");
	printf("\t-N                  Use NFC for card communication\n");
#endif // WITH_PCSC && WITH_NFC
	printf("\n");
	printf("\t-d                  Print debug output\n");
	printf("\n");
	printf("\t-h                  Print this help message\n");
	printf("\n");
	printf("\t-v                  Print the version number\n");
}

std::string get_pin(std::string msg)
{
	printf("\n");
	printf("=================================================\n");
	printf("            PIN VERIFICATION REQUIRED            \n");
	printf("=================================================\n");
	printf("\n");
	
	std::string PIN;
	
	do
	{ 
		PIN = getpass(msg.c_str());
		
		if (PIN.size() > 8)
		{
			printf("PIN too long; 8 characters or less expected!\n");
		}
		else if (PIN.empty())
		{
			printf("You must enter a PIN!\n");
		}
	}
	while (PIN.empty() || (PIN.size() > 8));
	
	printf("\n");
	
	return PIN;
}

bool communicate_with_card(silvia_card_channel* card, std::vector<bytestring>& commands, std::vector<bytestring>& results)
{
	printf("Communicating with the card... "); fflush(stdout);
		
	bool comm_ok = true;
	size_t cmd_ctr = 0;
	
	for (std::vector<bytestring>::iterator i = commands.begin(); (i != commands.end()) && comm_ok; i++)
	{	
		bytestring result;
		
		DEBUG_MSG("--> %s\n", i->hex_str().c_str());
		
		if (!card->transmit(*i, result))
		{
			comm_ok = false;
			break;
		}
		
		DEBUG_MSG("<-- %s\n", result.hex_str().c_str());
		
		cmd_ctr++;
		
        if (result.substr(result.size() - 2) == "6B00")
        {
            // This is a workaround for the fact that we have no idea how many attributes were in the current credential (we do not read the Issues spec)
            // With INS_ADMIN_ATTRIBUTE (getting attribute value), this error is returned if we ask more values than are present in this credential
            // Let's just continue for now, because who knows what we might request more in the future?
            // Because we bail out before the push_back, we do not store anything, so we don't show anything either.
            continue;
        }
		else if (result.substr(result.size() - 2) != "9000")
		{
			// Return values between 63C0--63CF indicate a wrong PIN
			const unsigned int PIN_attempts = ((result.substr(result.size() - 2) ^ "63C0")[0] << 8) | ((result.substr(result.size() - 2) ^ "63C0")[1]);
			if (PIN_attempts <= 0xF)
			{
				printf("wrong PIN, %u attempts remaining ", PIN_attempts);
			}
			else
			{
				printf("(0x%s) ", result.substr(result.size() - 2).hex_str().c_str());
			}
			comm_ok = false;
			break;
		}
		
		results.push_back(result);
	}
	
	if (comm_ok)
	{
		printf("OK\n");
	}
	else
	{
		printf("FAILED!\n");
	}
	
	return comm_ok;
}

bool read_log(silvia_card_channel* card, std::string userPIN)
{
	bool rv = true;

	std::vector<bytestring> commands;
	std::vector<bytestring> results;

	silvia_irma_manager irma_manager;

	commands = irma_manager.get_log_commands(userPIN);

	int n_ent = 1;
	
	if (communicate_with_card(card, commands, results))
	{
		int i = 2; // The first two results corresponds to SELECT and VERIFY APDUs.
	
		for (char start_entry = 0x00; start_entry < irma_manager.LOG_SIZE; start_entry = (char)(start_entry + irma_manager.LOG_ENTRIES_PER_APDU))
		{
			std::string entry = results[i].hex_str();
		
			
			for (int j = 0; j < irma_manager.LOG_ENTRIES_PER_APDU; j++)
			{
				std::string e = entry.substr(j*irma_manager.LOG_ENTRY_SIZE*2, irma_manager.LOG_ENTRY_SIZE*2);
				print_log_entry(n_ent++, e);
			}
			i++;
		}  
	
	} 
	else
	{
		printf("Failed to communicate with the card, was it removed prematurely?\n");
		
		rv = false;
	}
	
	return rv;
}

bool get_list_cred(silvia_card_channel* card, std::string userPIN)
{
	bool rv = true;

	std::vector<bytestring> commands;
	std::vector<bytestring> results;

	silvia_irma_manager irma_manager;

	commands = irma_manager.list_credentials_commands(userPIN);

	if (communicate_with_card(card, commands, results))
	{
		assert(results.size() == 3); // SELECT + VERIFY + LIST_CREDS 
		std::string creds = results[2].hex_str();
		
	        for (int i = 0; i < creds.size() - 4; i = i+4) {
	        	std::string cred = creds.substr(i, 4);
	
	        	std::stringstream cred_ss;
	        	int cred_int;   

	        	cred_ss << std::hex << cred;
	        	cred_ss >> cred_int;

	        	std::stringstream out;
	        	out << cred_int;

			printf("Slot #%d: %s\n", i/4, (cred == "0000") ? "-- EMPTY ENTRY --" : out.str().c_str());
		}
	}
	else
	{
		printf("Failed to communicate with the card, was it removed prematurely?\n");
		
		rv = false;
	}
	
	return rv;
}

bool update_admin_pin(silvia_card_channel* card, std::string old_pin, std::string new_pin)
{
	bool rv = true;

	std::vector<bytestring> commands;
	std::vector<bytestring> results;

	silvia_irma_manager irma_manager;

	commands = irma_manager.update_admin_pin_commands(old_pin, new_pin);

	if (!communicate_with_card(card, commands, results))
	{
		printf("Failed to communicate with the card, was it removed prematurely?\n");
		
		rv = false;
	}
	
	return rv;
}

bool update_cred_pin(silvia_card_channel* card, std::string admin_pin, std::string new_pin)
{
	bool rv = true;

	std::vector<bytestring> commands;
	std::vector<bytestring> results;

	silvia_irma_manager irma_manager;

	commands = irma_manager.update_cred_pin_commands(admin_pin, new_pin);

	if (!communicate_with_card(card, commands, results))
	{
		printf("Failed to communicate with the card, was it removed prematurely?\n");
		
		rv = false;
	}
	
	return rv;
}

bool delete_credential(silvia_card_channel* card, std::string credential, std::string userPIN)
{
	bool rv = true;

	std::vector<bytestring> commands;
	std::vector<bytestring> results;

	silvia_irma_manager irma_manager;

	commands = irma_manager.del_cred_commands(credential, userPIN);

	if (!communicate_with_card(card, commands, results))
	{
		printf("Failed to communicate with the card, was it removed prematurely?\n");
		rv = false;
	}
	
	return rv;
}


bool read_credential(silvia_card_channel* card, std::string cred, std::string userPIN)
{
	bool rv = true;

	std::vector<bytestring> commands;
	std::vector<bytestring> results;

	silvia_irma_manager irma_manager;

	commands = irma_manager.read_credential_commands(cred, userPIN); 

	if (!communicate_with_card(card, commands, results))
	{
		printf("Failed to communicate with the card, was it removed prematurely?\n");
		rv = false;
	} else {
		for (int i = 3; i < results.size(); i++) {
		
			// Remove 0x9000
			std::string attr_hex = results[i].hex_str().substr(0, results[i].hex_str().size() - 4);;

			// Remove 0's
			std::string::size_type pos =  attr_hex.find_first_not_of('0', 0);

			if(pos > 0)
				attr_hex.erase(0, pos); 

			if (i == 3) {
				print_timestamp_irma("Expiration date", results[i]);
			} else {
				std::string attr_ascii;

				for (int j = 0; j < attr_hex.length(); j += 2)
					attr_ascii.push_back(strtol(attr_hex.substr(j, 2).c_str(), NULL, 16));
		
					printf("Attribute [%i]: %s\n", (i-3), attr_ascii.c_str());
			}
		}
	}
	
	return rv;
}

void do_manager(int channel_type, int opt, std::string credential)
{
	silvia_card_channel* card = NULL;
	
	printf("Silvia command-line IRMA manager %s\n\n", VERSION);

	// Wait for card
	printf("\n********************************************************************************\n");
	printf("Waiting for card");
	
#ifdef WITH_PCSC
	if (channel_type == SILVIA_CHANNEL_PCSC)
	{
		printf(" (PCSC) ..."); fflush(stdout);
		
		silvia_pcsc_card* pcsc_card = NULL;
		
		if (!silvia_pcsc_card_monitor::i()->wait_for_card(&pcsc_card))
		{
			printf("FAILED, exiting\n");
			
			exit(-1);
		}
		
		card = pcsc_card;
	}
#endif // WITH_PCSC
#ifdef WITH_NFC
	if (channel_type == SILVIA_CHANNEL_NFC)
	{
		printf(" (NFC) ..."); fflush(stdout);
		
		silvia_nfc_card* nfc_card = NULL;
		
		if (!silvia_nfc_card_monitor::i()->wait_for_card(&nfc_card))
		{
			printf("FAILED, exiting\n");
			
			exit(-1);
		}
		
		card = nfc_card;
	}
#endif // WITH_NFC
		
	printf("OK\n");
	
	if (opt == MANAGER_OPT_LOG) {
		// Ask the user to enter their PIN
		std::string PIN = get_pin("Please enter your administration PIN: ");

		read_log(card, PIN);

		printf("OK\n");
	} else if (opt == MANAGER_OPT_CRED) {
		// Ask the user to enter their PIN
		std::string PIN = get_pin("Please enter your administration PIN: ");

		get_list_cred(card, PIN);

		printf("OK\n");
	} else if (opt == MANAGER_OPT_UPDATE_ADMIN) {
		// Ask the user to enter their PIN
		std::string old_pin = get_pin("Please enter your current administration PIN: ");
		std::string new_pin = get_pin("Please enter your new administration PIN: ");

		update_admin_pin(card, old_pin, new_pin);

		printf("OK\n");

	} else if (opt == MANAGER_OPT_UPDATE_CRED) {
		// Ask the user to enter their PIN
		std::string admin_pin = get_pin("Please enter your current administration PIN: ");
		std::string new_pin = get_pin("Please enter your new credential PIN: ");

		update_cred_pin(card, admin_pin, new_pin);

		printf("OK\n");

	} else if (opt == MANAGER_OPT_DEL_CRED) {
		// Ask the user to enter their PIN
		std::string pin = get_pin("Please enter your administration PIN: ");

		delete_credential(card, credential, pin);

		printf("OK\n");

	} else if (opt == MANAGER_OPT_READ_CRED) {
		// Ask the user to enter their PIN
		std::string pin = get_pin("Please enter your administration PIN: ");

		read_credential(card, credential, pin);

		printf("OK\n");
	}
	
	printf("********************************************************************************\n");
	delete card;
}

		
int main(int argc, char* argv[])
{

	std::string credential;
	std::string attribute;

	int c = 0;

	int read_cred = 0;
	int get_log = 0;
	int get_cred = 0;
	int update_admin_pin = 0;
	int update_cred_pin = 0;
	int del_cred = 0;
#if defined(WITH_PCSC) && defined(WITH_NFC)
	int channel_type = SILVIA_CHANNEL_PCSC;
#elif defined(WITH_PCSC)
	int channel_type = SILVIA_CHANNEL_PCSC;
#elif defined(WITH_NFC)
	int channel_type = SILVIA_CHANNEL_NFC;
#endif
	
#if defined(WITH_PCSC) && defined(WITH_NFC)
	while ((c = getopt(argc, argv, "r:caso:lhvPN")) != -1)
#else
	while ((c = getopt(argc, argv, "r:caso:lhv")) != -1)
#endif
	{
		switch (c)
		{
		case 'h':
			usage();
			return 0;
		case 'v':
			version();
			return 0;
		case 'l':
			get_log = 1;
			break;
		case 's':
			get_cred = 1;
			break;
		case 'a':
			update_admin_pin = 1;
			break;
		case 'c':
			update_cred_pin = 1;
			break;
		case 'o':
			read_cred = 1;
			credential = std::string(optarg);
			break;
		case 'r':
			del_cred = 1;
			credential = std::string(optarg);
			break;
#if defined(WITH_PCSC) && defined(WITH_NFC)
		case 'P':
			channel_type = SILVIA_CHANNEL_PCSC;
			break;
		case 'N':
			channel_type = SILVIA_CHANNEL_NFC;
			break;
#endif
		case 'd':
			debug_output = true;
			break;
		}
	}
		
#ifdef WITH_NFC
	if (channel_type == SILVIA_CHANNEL_NFC)
	{
		// Handle signals when using NFC; this prevents the NFC reader
		// from going into an undefined state when the user aborts the
		// program by pressing Ctrl+C
		signal(SIGQUIT, signal_handler);
		signal(SIGTERM, signal_handler);
		signal(SIGINT, signal_handler);
		signal(SIGABRT, signal_handler);
	}
#endif

		if (get_log == 1 && get_cred == 0 && update_admin_pin == 0 && del_cred == 0 && update_cred_pin == 0 && read_cred == 0)
			do_manager(channel_type, MANAGER_OPT_LOG, "");
		else if (get_log == 0 && get_cred == 1 && update_admin_pin == 0 && del_cred == 0 && update_cred_pin == 0 && read_cred == 0)
			do_manager(channel_type, MANAGER_OPT_CRED, "");
		else if (get_log == 0 && get_cred == 0 && update_admin_pin == 1 && del_cred == 0 && update_cred_pin == 0 && read_cred == 0)
			do_manager(channel_type, MANAGER_OPT_UPDATE_ADMIN, "");
		else if (get_log == 0 && get_cred == 0 && update_admin_pin == 0 && del_cred == 1 && update_cred_pin == 0 && read_cred == 0)
			do_manager(channel_type, MANAGER_OPT_DEL_CRED, credential); 
		else if (get_log == 0 && get_cred == 0 && update_admin_pin == 0 && del_cred == 0 && update_cred_pin == 1 && read_cred == 0)
			do_manager(channel_type, MANAGER_OPT_UPDATE_CRED, ""); 
		else if (get_log == 0 && get_cred == 0 && update_admin_pin == 0 && del_cred == 0 && update_cred_pin == 0 && read_cred == 1)
			do_manager(channel_type, MANAGER_OPT_READ_CRED, credential); 
		else {
			usage();
			return 0;	
		}
	
	return 0;
}
