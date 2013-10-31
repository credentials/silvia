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
 silvia_verifier.cpp

 Command-line verifier utility
 *****************************************************************************/

#include "config.h"
#include "silvia_parameters.h"
#include "silvia_irma_verifier.h"
#ifdef WITH_PCSC
#include "silvia_pcsc_card.h"
#endif // WITH_PCSC
#ifdef WITH_NFC
#include "silvia_nfc_card.h"
#endif // WITH_NFC
#include "silvia_card_channel.h"
#include "silvia_irma_xmlreader.h"
#include "silvia_idemix_xmlreader.h"
#include "silvia_types.h"
#include <string>
#include <iostream>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <signal.h>

const char* weekday[7] = { "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday" };

const char* month[12] = { "January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December" };

void signal_handler(int signal)
{
	// Exit on any signal we receive and handle
	fprintf(stderr, "\nCaught signal, exiting...\n");
	
	exit(0);
}

void set_parameters()
{
	////////////////////////////////////////////////////////////////////
	// Set the system parameters in the IRMA library; this function must
	// be updated if we ever change the parameters for IRMA cards!!!
	////////////////////////////////////////////////////////////////////
	
	silvia_system_parameters::i()->set_l_n(1024);
	silvia_system_parameters::i()->set_l_m(256);
	silvia_system_parameters::i()->set_l_statzk(80);
	silvia_system_parameters::i()->set_l_H(256);
	silvia_system_parameters::i()->set_l_v(1700);
	silvia_system_parameters::i()->set_l_e(597);
	silvia_system_parameters::i()->set_l_e_prime(120);
	silvia_system_parameters::i()->set_hash_type("sha256");
}

void version(void)
{
	printf("The Simple Library for Verifying and Issuing Attributes (silvia)\n");
	printf("\n");
	printf("Command-line verification utility for IRMA cards %s\n", VERSION);
	printf("\n");
	printf("Copyright (c) 2013 Roland van Rijswijk-Deij\n\n");
	printf("Use, modification and redistribution of this software is subject to the terms\n");
	printf("of the license agreement. This software is licensed under a 2-clause BSD-style\n");
	printf("license a copy of which is included as the file LICENSE in the distribution.\n");
}

void usage(void)
{
	printf("Silvia command-line IRMA verifier %s\n\n", VERSION);
	printf("Usage:\n");
	printf("\tsilvia_verifier -I <issuer-spec> -V <verifier-spec> -k <issuer-pubkey> [-p]");
#if defined(WITH_PCSC) && defined(WITH_NFC)
	printf(" [-P] [-N]");
#endif // WITH_PCSC && WITH_NFC
	printf("\n");
	printf("\tsilvia_keygen -h\n");
	printf("\tsilvia_keygen -v\n");
	printf("\n");
	printf("\t-I <issuer-spec>   Read issuer specification from <issuer-spec>\n");
	printf("\t-V <verifier-spec> Read verifier specification from <verifier-spec>\n");
	printf("\t-k <issuer-pubkey> Read issuer public key from <issuer-pubkey>\n");
	printf("\t-p                 Force PIN verification\n");
#if defined(WITH_PCSC) && defined(WITH_NFC)
	printf("\t-P                 Use PC/SC for card communication (default)\n");
	printf("\t-N                 Use NFC for card communication\n");
#endif // WITH_PCSC && WITH_NFC
	printf("\n");
	printf("\t-h                 Print this help message\n");
	printf("\n");
	printf("\t-v                 Print the version number\n");
}

bool verify_pin(silvia_card_channel* card)
{
	printf("\n");
	printf("=================================================\n");
	printf("            PIN VERIFICATION REQUIRED            \n");
	printf("=================================================\n");
	printf("\n");
	
	
	std::string PIN;
	
	do
	{ 
		PIN = getpass("Please enter your PIN: ");
		
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
	printf("Verifying PIN... "); fflush(stdout);
	
	bytestring verify_pin_apdu = "0020000008";
	
	for (std::string::iterator i = PIN.begin(); i != PIN.end(); i++)
	{
		verify_pin_apdu += (unsigned char) *i;
	}
	
	while (verify_pin_apdu.size() < 13)
	{
		verify_pin_apdu += "00";
	}
	
	bytestring data;
	unsigned short sw;
	
	if (!card->transmit(verify_pin_apdu, data, sw))
	{
		printf("FAILED (card communication)\n");
		
		return false;
	}
	
	if (sw == 0x9000)
	{
		printf("OK\n");
		
		return true;
	}
	else if ((sw >= 0x63C0) && (sw <= 0x63CF))
	{
		printf("FAILED (%u attempts remaining)\n", sw - 0x63C0);
	}
	else
	{
		printf("FAILED (card error 0x%04X)\n", sw);
	}
	
	return false;
}

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

bool communicate_with_card(silvia_card_channel* card, std::vector<bytestring>& commands, std::vector<bytestring>& results, bool force_pin)
{
	printf("Communicating with the card... "); fflush(stdout);
		
	bool comm_ok = true;
	size_t cmd_ctr = 0;
	
	for (std::vector<bytestring>::iterator i = commands.begin(); (i != commands.end()) && comm_ok; i++)
	{	
		bytestring result;
		
		if (!card->transmit(*i, result))
		{
			comm_ok = false;
			break;
		}
		
		cmd_ctr++;
		
		if ((force_pin) && (cmd_ctr == 1))
		{
			if (!verify_pin(card))
			{
				comm_ok = false;
				break;
			}
			
			printf("Communicating with the card... "); fflush(stdout);
		}
		else if (result.substr(result.size() - 2) == "6982")
		{
			// The card wants us to enter a PIN before producing the proof
			if (!verify_pin(card))
			{
				comm_ok = false;
				break;
			}
			
			printf("Communicating with the card... "); fflush(stdout);
			
			// Re-execute the command
			if (!card->transmit(*i, result))
			{
				comm_ok = false;
				break;
			}
		}
		else if ((result.substr(result.size() - 2) != "9000") && 
		         (result.substr(result.size() - 2) != "6A82") &&
		         (result.substr(result.size() - 2) != "6D00"))
		{
			printf("(0x%s) ", result.substr(result.size() - 2).hex_str().c_str());
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

void verifier_loop(std::string issuer_spec, std::string verifier_spec, std::string issuer_pubkey, bool force_pin, int channel_type)
{
	silvia_card_channel* card = NULL;
	
	printf("Silvia command-line IRMA verifier %s\n\n", VERSION);
		
	// Read configuration files
	silvia_verifier_specification* vspec = silvia_irma_xmlreader::i()->read_verifier_spec(issuer_spec, verifier_spec);
	
	if (vspec == NULL)
	{
		fprintf(stderr, "Failed to read issuer and verifier specification\n");
		
		return;
	}
	
	silvia_pub_key* pubkey = silvia_idemix_xmlreader::i()->read_idemix_pubkey(issuer_pubkey);
	
	if (pubkey == NULL)
	{
		fprintf(stderr, "Failed to read issuer public key\n");
		
		delete vspec;
		
		return;
	}
	
	// Create verifier object
	silvia_irma_verifier verifier(pubkey, vspec);
	
	while (true)
	{
		printf("\n********************************************************************************\n");
		printf("%s: %s\n\n", vspec->get_verifier_name().c_str(), vspec->get_short_msg().c_str());
		
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
		
		// First, perform application selection
		std::vector<bytestring> commands;
		std::vector<bytestring> results;
		
		commands = verifier.get_select_commands();
		
		if (communicate_with_card(card, commands, results, false))
		{
			if (verifier.submit_select_data(results))
			{
				// Now, perform the actual verification
				commands.clear();
				results.clear();
				
				commands = verifier.get_proof_commands();
				
				if (communicate_with_card(card, commands, results, force_pin))
				{
					printf("Verifying proof... "); fflush(stdout);
				
					std::vector<std::pair<std::string, bytestring> > revealed;
					
					if (verifier.submit_and_verify(results, revealed))
					{
						printf("OK\n");
						
						printf("\n");
						
						if (revealed.size() > 0)
						{
							printf("Revealed attributes:\n\n");
							
							printf("Attribute           |Value\n");
							printf("--------------------+-----------------------------------------------------------\n");
							
							std::vector<std::pair<std::string, bytestring> >::iterator i = revealed.begin();
							
							// Check if the first attribute is "expires"
							if (i->first == "expires")
							{
								time_t expires = (i->second[i->second.size() - 2] << 8) + (i->second[i->second.size() - 1]);
								expires *= 86400; // convert days to seconds
								
								struct tm* date = gmtime(&expires);
								
								printf("%-20s|%s %s %d %d\n", i->first.c_str(),
									weekday[date->tm_wday],
									month[date->tm_mon],
									date->tm_mday,
									date->tm_year + 1900);
								
								i++;
							}
							
							// Assume the other attributes are strings
							for (; i != revealed.end(); i++)
							{
								printf("%-20s|%-59s\n", i->first.c_str(), (const char*) bs2str(i->second).byte_str());
							}
							
							printf("\n");
						}
					}
					else
					{
						printf("FAILED\n");
					}
				}
				else
				{
					verifier.abort();
				}
			}
			else
			{
				printf("Failed to select IRMA application!\n");
				
				verifier.abort();
			}
		}
		else
		{
			verifier.abort();
		}
		
		printf("Waiting for card to be removed... "); fflush(stdout);
		
		while (card->status())
		{
			usleep(10000);
		}
		
		printf("OK\n");
		
		printf("********************************************************************************\n");
		
		delete card;
	}
	
	delete vspec;
	delete pubkey;
}

int main(int argc, char* argv[])
{
	// Set library parameters
	set_parameters();
	
	// Program parameters
	std::string issuer_spec;
	std::string verifier_spec;
	std::string issuer_pubkey;
	bool force_pin = false;
	int c = 0;
#if defined(WITH_PCSC) && defined(WITH_NFC)
	int channel_type = SILVIA_CHANNEL_PCSC;
#elif defined(WITH_PCSC)
	int channel_type = SILVIA_CHANNEL_PCSC;
#elif defined(WITH_NFC)
	int channel_type = SILVIA_CHANNEL_NFC;
#endif
	
#if defined(WITH_PCSC) && defined(WITH_NFC)
	while ((c = getopt(argc, argv, "I:V:k:phvPN")) != -1)
#else
	while ((c = getopt(argc, argv, "I:V:k:phv")) != -1)
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
		case 'I':
			issuer_spec = std::string(optarg);
			break;
		case 'V':
			verifier_spec = std::string(optarg);
			break;
		case 'k':
			issuer_pubkey = std::string(optarg);
			break;
		case 'p':
			force_pin = true;
			break;
#if defined(WITH_PCSC) && defined(WITH_NFC)
		case 'P':
			channel_type = SILVIA_CHANNEL_PCSC;
			break;
		case 'N':
			channel_type = SILVIA_CHANNEL_NFC;
			break;
#endif
		}
	}
	
	if (issuer_spec.empty())
	{
		fprintf(stderr, "No issuer specification file specified!\n");
		
		return -1;
	}
	
	if (verifier_spec.empty())
	{
		fprintf(stderr, "No verifier specification file specified!\n");
		
		return -1;
	}
	
	if (issuer_pubkey.empty())
	{
		fprintf(stderr, "No issuer public key file specified!\n");
		
		return -1;
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
	
	verifier_loop(issuer_spec, verifier_spec, issuer_pubkey, force_pin, channel_type);
	
	return 0;
}
