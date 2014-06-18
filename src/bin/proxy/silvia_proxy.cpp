/* $Id$ */

/*
 * Copyright (c) 2014 Patrick Uiterwijk
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
#ifdef WITH_PCSC
#include "silvia_pcsc_card.h"
#endif // WITH_PCSC
#ifdef WITH_NFC
#include "silvia_nfc_card.h"
#endif // WITH_NFC
#include "silvia_card_channel.h"
#include "silvia_types.h"
#include <string>
#include <iostream>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <signal.h>

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
    printf("Command-line card proxy for IRMA cards %s\n", VERSION);
    printf("\n");
    printf("Copyright (c) 2014 Patrick Uiterwijk\n\n");
    printf("Use, modification and redistribution of this software is subject to the terms\n");
    printf("of the license agreement. This software is licensed under a 2-clause BSD-style\n");
    printf("license a copy of which is included as the file LICENSE in the distribution.\n");
}

void usage(void)
{
	printf("Silvia command-line IRMA card proxy %s\n\n", VERSION);
	printf("Usage:\n");
	printf("\tsilvia_proxy");
#if defined(WITH_PCSC) && defined(WITH_NFC)
	printf(" [-P] [-N]");
#endif // WITH_PCSC && WITH_NFC
	printf("\n");
	printf("\tsilvia_verifier -h\n");
	printf("\tsilvia_verifier -v\n");
	printf("\n");
#if defined(WITH_PCSC) && defined(WITH_NFC)
	printf("\t-P                 Use PC/SC for card communication (default)\n");
	printf("\t-N                 Use NFC for card communication\n");
#endif // WITH_PCSC && WITH_NFC
	printf("\n");
	printf("\t-h                 Print this help message\n");
	printf("\n");
	printf("\t-v                 Print the version number\n");
}

void proxy(int channel_type)
{
	silvia_card_channel* card = NULL;

    printf("control wait-for-card ");
    fflush(stdout);

#ifdef WITH_PCSC
    if (channel_type == SILVIA_CHANNEL_PCSC)
    {
        printf("pcsc\n");
        fflush(stdout);
        
        silvia_pcsc_card* pcsc_card = NULL;
        
        if (!silvia_pcsc_card_monitor::i()->wait_for_card(&pcsc_card))
        {
            printf("\nerror no-card\n");
            fflush(stdout);
            
            exit(-1);
        }
        
        card = pcsc_card;
    }
#endif // WITH_PCSC
#ifdef WITH_NFC
    if (channel_type == SILVIA_CHANNEL_NFC)
    {
        printf("nfc\n");
        fflush(stdout);
        
        silvia_nfc_card* nfc_card = NULL;
        
        if (!silvia_nfc_card_monitor::i()->wait_for_card(&nfc_card))
        {
            printf("\nerror no-card\n");
            fflush(stdout);
            
            exit(-1);
        }
        
        card = nfc_card;
    }
#endif // WITH_NFC
        
    printf("control connected\n");
    fflush(stdout);
    
    while(!std::cin.eof())
    {
        std::string request_type;
        std::string request;
        std::cin >> request_type;
        if(request_type.compare("request") != 0)
        {
            printf("error non-request\n");
            fflush(stdout);
            exit(-1);
        }
        std::cin >> request;

        if(request.compare("") != 0)
        {
            bytestring requestbs = bytestring(request.c_str());
            bytestring result;
            if(!card->transmit(requestbs, result))
            {
                printf("error transmit-error\n");
                fflush(stdout);
                exit(-1);
            }
            printf("response %s\n", result.hex_str().c_str());
            fflush(stdout);
        }
        

    }

    printf("control wait-for-remove\n");
    fflush(stdout);
    
    while (card->status())
    {
        usleep(10000);
    }
    
    delete card;
}

int main(int argc, char* argv[])
{
	int c = 0;
#if defined(WITH_PCSC) && defined(WITH_NFC)
	int channel_type = SILVIA_CHANNEL_PCSC;
#elif defined(WITH_PCSC)
	int channel_type = SILVIA_CHANNEL_PCSC;
#elif defined(WITH_NFC)
	int channel_type = SILVIA_CHANNEL_NFC;
#endif
	
#if defined(WITH_PCSC) && defined(WITH_NFC)
	while ((c = getopt(argc, argv, "hvPN")) != -1)
#else
	while ((c = getopt(argc, argv, "hv")) != -1)
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
#if defined(WITH_PCSC)
		case 'P':
			channel_type = SILVIA_CHANNEL_PCSC;
			break;
#endif
#if defined(WITH_NFC)
		case 'N':
			channel_type = SILVIA_CHANNEL_NFC;
			break;
#endif
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
	
	proxy(channel_type);
	
	return 0;
}
