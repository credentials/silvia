/* $Id$ */

/*
 * Copyright (c) 2014 Antonio de la Piedra
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
#include "silvia_irma_issuer.h"
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

const int LOG_SIZE = 30;
const int LOG_ENTRY_SIZE = 16;
const char LOG_ENTRIES_PER_APDU = 255 / 16;   

/* Log entries */

const int IDX_TIMESTAMP = 0;
const int SIZE_TIMESTAMP = 4;
const int IDX_TERMINAL = 4;
const int SIZE_TERMINAL = 4;
const int IDX_ACTION = 8;
const int IDX_CREDENTIAL = 9;  
const int IDX_SELECTION = 11;

const unsigned char ACTION_NONE = 0x00;
const unsigned char ACTION_ISSUE = 0x01;
const unsigned char ACTION_PROVE = 0x02;
const unsigned char ACTION_REMOVE = 0x03;

//http://forums.codeguru.com/showthread.php?316299-C-General-What-are-different-number-representations

void string_to_vector(std::string str, std::vector<int> &array)
{
	int length = str.length();
	// make sure the input string has an even digit numbers
	if(length%2 == 1)
	{
		str = "0" + str;
		length++;
	}

	// allocate memory for the output array
	array.reserve(length/2);
	
	std::stringstream sstr(str);
	for(int i=0; i < length/2; i++)
	{
		char ch1, ch2;
		sstr >> ch1 >> ch2;
		int dig1, dig2;
		if(isdigit(ch1)) dig1 = ch1 - '0';
		else if(ch1>='A' && ch1<='F') dig1 = ch1 - 'A' + 10;
		else if(ch1>='a' && ch1<='f') dig1 = ch1 - 'a' + 10;
		if(isdigit(ch2)) dig2 = ch2 - '0';
		else if(ch2>='A' && ch2<='F') dig2 = ch2 - 'A' + 10;
		else if(ch2>='a' && ch2<='f') dig2 = ch2 - 'a' + 10;
		array.push_back(dig1*16 + dig2);
	}
}

/* 
   print_log_entry(std::string) is based on IdemixLogEntry, 
   Copyright (C) Wouter Lueks, Radboud University Nijmegen, March 2013.
*/

void print_log_entry(int n, std::string e) 
{
	std::vector<int> array;
	string_to_vector(e.c_str(), array);

	printf("Entry %d: ", n);

	switch(array[IDX_ACTION]) 
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

	unsigned int x;   
	unsigned int cred_int;   

	std::stringstream ss;
	ss << std::hex << timestamp;
	ss >> x;

	std::stringstream ss2;
	ss2 << std::hex << credential;
	ss2 >> cred_int;

	time_t now = x;
	char* dt = ctime(&now);

	if (array[IDX_ACTION] == ACTION_PROVE)
		printf("Policy: %s\n", mask.c_str());	
			
	printf("Credential: %d\n", cred_int);
	printf("Timestamp: %s\n", dt);
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
	printf("\tsilvia_manager [-ilrac] <credential> [-p] <pin> [-u] <old pin> <new pin>");
#if defined(WITH_PCSC) && defined(WITH_NFC)
	printf(" [-P] [-N]");
#endif // WITH_PCSC && WITH_NFC
	printf("\n");
	printf("\tsilvia_manager -l			\t\t\tRead the log of the IRMA card\n");
	printf("\tsilvia_manager -r <credential> -p <admin pin>	\t\tRemove a credential form the card\n");
	printf("\tsilvia_manager -a -u [old admin pin] [new admin pin] \t\tUpdate admin pin\n");
	printf("\tsilvia_manager -c -u [old credential pin] [new credential pin]  Update credential pin\n");
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

std::string get_pin()
{
	printf("\n");
	printf("=================================================\n");
	printf("            PIN VERIFICATION REQUIRED            \n");
	printf("=================================================\n");
	printf("\n");
	
	std::string PIN;
	
	do
	{ 
		PIN = getpass("Please enter your administration PIN: ");
		
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
/*
bytestring bs2str(const bytestring& in)
{
	bytestring out = in;
	
	// Strip leading 00's
	while ((out.size() > 0) && (out[0] == 0x00))
	{
		out = out.substr(1);
	}
	
	// Append null-termination
	out += 0x00;
	
	return out;
}
*/

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
		
		if (result.substr(result.size() - 2) != "9000")
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

bool issue_one_credential(silvia_card_channel* card, std::string userPIN)
{
	bool rv = true;

	std::vector<bytestring> commands;
	std::vector<bytestring> results;


	assert(userPIN.size() <= 8);
	
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
	
	memcpy(&pin_data[0], userPIN.c_str(), userPIN.size());
	
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

	int n_ent = 1;
	
	if (communicate_with_card(card, commands, results))
	{
		int i = 2; // The first two results corresponds to SELECT and VERIFY APDUs.
	
		for (char start_entry = 0x00; start_entry < LOG_SIZE; start_entry = (char)(start_entry + LOG_ENTRIES_PER_APDU))
		{
			std::string entry = results[i].hex_str();
		
			
			for (int j = 0; j < LOG_ENTRIES_PER_APDU; j++)
			{
				std::string e = entry.substr(j*LOG_ENTRY_SIZE*2, LOG_ENTRY_SIZE*2);
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

void do_info(int channel_type)
{
	silvia_card_channel* card = NULL;
	
	printf("Silvia command-line IRMA issuer %s\n\n", VERSION);

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
	
	// Ask the user to enter their PIN
	std::string PIN = get_pin();

	//// Issue the credential
	issue_one_credential(card, PIN);

	printf("OK\n");
	
	printf("********************************************************************************\n");
	delete card;
}
		
int main(int argc, char* argv[])
{

	//std::string issue_script;
	int c = 0;
	int get_log = 0;
#if defined(WITH_PCSC) && defined(WITH_NFC)
	int channel_type = SILVIA_CHANNEL_PCSC;
#elif defined(WITH_PCSC)
	int channel_type = SILVIA_CHANNEL_PCSC;
#elif defined(WITH_NFC)
	int channel_type = SILVIA_CHANNEL_NFC;
#endif
	
#if defined(WITH_PCSC) && defined(WITH_NFC)
	while ((c = getopt(argc, argv, "lhvPN")) != -1)
#else
	while ((c = getopt(argc, argv, "lhv")) != -1)
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

		if (get_log)
			do_info(channel_type);
		else {
			usage();
			return 0;	
		}
	
	return 0;
}
