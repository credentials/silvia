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
 silvia_loader.cpp

 Command-line loader utility
 *****************************************************************************/

#include "config.h"
#include "silvia_pcsc_card.h"
#include "silvia_card_channel.h"
#include "silvia_types.h"
#include <string>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <signal.h>

void version(void)
{
	printf("The Simple Library for Verifying and Issuing Attributes (silvia)\n");
	printf("\n");
	printf("Command-line loader utility for IRMA cards %s\n", VERSION);
	printf("\n");
	printf("Copyright (c) 2013 Roland van Rijswijk-Deij\n\n");
	printf("Use, modification and redistribution of this software is subject to the terms\n");
	printf("of the license agreement. This software is licensed under a 2-clause BSD-style\n");
	printf("license a copy of which is included as the file LICENSE in the distribution.\n");
}

void usage(void)
{
	printf("Silvia command-line IRMA loader %s\n\n", VERSION);
	printf("Usage:\n");
	printf("\tsilvia_loader -f <loader-log>");
	printf("\n");
	printf("\tsilvia_loader -h\n");
	printf("\tsilvia_loader -v\n");
	printf("\n");
	printf("\t-l <loader-log> Replay the specified loader log to the card>\n");
	printf("\n");
	printf("\t-h              Print this help message\n");
	printf("\n");
	printf("\t-v              Print the version number\n");
}

bool transceive(silvia_pcsc_card* card, bytestring& command, unsigned short expected_sw)
{
	size_t cmd_ctr = 0;

	printf("--> %s\n", command.hex_str().c_str());

	bytestring result;

	if (!card->transmit(command, result))
	{
		return false;
	}

	if (result.size() < 2)
	{
		return false;
	}

	unsigned short sw = result[result.size() - 2] << 8;
	sw += result[result.size() - 1];

	printf("<-- %04X\n", sw);

	return (sw == expected_sw);
}

int replay_log(std::string& loader_log)
{
	printf("Silvia command-line IRMA loader %s\n\n", VERSION);
		
	printf("\n********************************************************************************\n");
	printf("Waiting for card (PCSC) ..."); fflush(stdout);
		
	silvia_pcsc_card* pcsc_card = NULL;
			
	if (!silvia_pcsc_card_monitor::i()->wait_for_card(&pcsc_card))
	{
		printf("FAILED, exiting\n");
				
		return -1;
	}
	printf("OK\n");

	/* Open log file */
	FILE* log = fopen(loader_log.c_str(), "r");

	if (log == NULL)
	{
		fprintf(stderr, "Failed to open %s for reading\n", loader_log.c_str());

		return -1;
	}

	/* Read the loader log and replay it to the card */
	char buf[8192] = { 0 };

	while (!feof(log))
	{
		if (fgets(buf, 8192, log) == NULL)
		{
			printf("Reached the end of the log file\n");

			return 0;
		}

		std::string log_line = std::string(buf);

		/* Check if this is a "Send" line */
		if (log_line.substr(0, 6) == "Send: ")
		{
			std::string send = log_line.substr(6);

			/* Read another line */
			if (fgets(buf, 8192, log) == NULL)
			{
				fprintf(stderr, "File terminated before expect Recv line\n");

				return -1;
			}

			log_line = std::string(buf);

			if (log_line.substr(0, 6) == "Recv: ")
			{
				std::string recv = log_line.substr(6);

				/* Now, get the actual data to send */
				std::string data_to_send;

				while((send.size() > 0) && (send[0] > 32) && (send[0] < 127))
				{
					data_to_send += send[0];
					send = send.substr(1);
				}

				/* And find out what status word is expected back */
				unsigned short sw = 0;

				while((recv.size() > 0) && (recv[0] != '(')) recv = recv.substr(1);

				if (recv.size() < 6)
				{
					fprintf(stderr, "Recv line malformed, status word not found\n");

					return -1;
				}

				recv = recv.substr(1);

				for (int i = 0; i < 4; i++)
				{
					sw = sw << 4;
					sw += (unsigned char) (recv[i] - 0x30);
				}

				bytestring to_send = data_to_send.c_str();

				if (!transceive(pcsc_card, to_send, sw))
				{
					fprintf(stderr, "Command exchange with card failed, exiting\n");

					return -1;
				}
			}
			else
			{
				fprintf(stderr, "Expected a Recv line!\n");

				continue;
			}
		}
	}

	return 0;
}

int main(int argc, char* argv[])
{
	// Program parameters
	std::string loader_log;
	int c = 0;
	
	while ((c = getopt(argc, argv, "f:hv")) != -1)
	{
		switch (c)
		{
		case 'h':
			usage();
			return 0;
		case 'v':
			version();
			return 0;
		case 'f':
			loader_log = std::string(optarg);
			break;
		}
	}
	
	if (loader_log.empty())
	{
		fprintf(stderr, "No issuer loader log file specified!\n");
		
		return -1;
	}

	return replay_log(loader_log);
}
