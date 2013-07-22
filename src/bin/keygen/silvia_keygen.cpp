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
 silvia_keygen.cpp

 Issuer key generation utility
 *****************************************************************************/

#include "config.h"
#include "silvia_issuer_keygen.h"
#include "silvia_parameters.h"
#include "silvia_macros.h"
#include <string>
#include <unistd.h>

// Default modulus size for new keys
#define DEFAULT_BITSIZE 2048

void version(void)
{
	printf("The Simple Library for Verifying and Issuing Attributes (silvia)\n");
	printf("\n");
	printf("Issuer key generation utility version %s\n", VERSION);
	printf("\n");
	printf("Copyright (c) 2013 Roland van Rijswijk-Deij\n\n");
	printf("Use, modification and redistribution of this software is subject to the terms\n");
	printf("of the license agreement. This software is licensed under a 2-clause BSD-style\n");
	printf("license a copy of which is included as the file LICENSE in the distribution.\n");
}

void usage(void)
{
	printf("Silvia issuer key generation utility %s\n\n", VERSION);
	printf("Usage:\n");
	printf("\tsilvia_keygen -a <#-attribs> [-n <bits>] [-p <file>] [-P <file>]\n");
	printf("\tsilvia_keygen -h\n");
	printf("\tsilvia_keygen -v\n");
	printf("\n");
	printf("\t-a <#-attribs> Generate a key-pair supporting credentials with at most\n");
	printf("\t               <#-attribs> attributes per credentials\n");
	printf("\t-n <bits>      Generate a key-pair with a <bits>-bit modulus (defaults\n");
	printf("\t               to %d)\n", DEFAULT_BITSIZE);
	printf("\t-p <file>      Output the public key to <file> (defaults to stdout)\n");
	printf("\t-P <file>      Output the private key to <file> (defaults to stdout)\n");
	printf("\n");
	printf("\t-h             Print this help message\n");
	printf("\n");
	printf("\t-v             Print the version number\n");
}

int generate_key_pair(FILE* pub_key_file, FILE* priv_key_file, size_t num_attribs, size_t bit_size)
{
	printf("Generating %zd-bit issuer key pair for %zd attributes ... ", bit_size, num_attribs); fflush(stdout);
	
	// Set key size
	silvia_system_parameters::i()->set_l_n(bit_size);
	
	// Generate key-pair
	silvia_pub_key* pub_key;
	silvia_priv_key* priv_key;
	
	silvia_issuer_keyfactory::i()->generate_keypair(num_attribs, &pub_key, &priv_key);
	
	printf("OK\n");
	
	// Output the public key
	fprintf(pub_key_file, "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n");
	fprintf(pub_key_file, "<IssuerPublicKey xmlns=\"http://www.zurich.ibm.com/security/idemix\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"http://www.zurich.ibm.com/security/idemix IssuerPublicKey.xsd\">\n");
	fprintf(pub_key_file, "  <References>\n");
    fprintf(pub_key_file, "    <GroupParameters>http://www.zurich.ibm.com/security/idmx/v2/gp.xml</GroupParameters>\n");
	fprintf(pub_key_file, "  </References>\n");
	fprintf(pub_key_file, "  <Elements>\n");
    fprintf(pub_key_file, "    <S>"); fprintmpzdec(pub_key_file, pub_key->get_S()); fprintf(pub_key_file, "</S>\n");
    fprintf(pub_key_file, "    <Z>"); fprintmpzdec(pub_key_file, pub_key->get_Z()); fprintf(pub_key_file, "</Z>\n");
    fprintf(pub_key_file, "    <n>"); fprintmpzdec(pub_key_file, pub_key->get_n()); fprintf(pub_key_file, "</n>\n");
    fprintf(pub_key_file, "    <Bases num=\"%zd\">\n", num_attribs);
    
    for (size_t i = 0; i < num_attribs; i++)
    {
		fprintf(pub_key_file, "      <Base_%zd>", i); fprintmpzdec(pub_key_file, pub_key->get_R()[i]); fprintf(pub_key_file, "</Base_%zd>\n", i);
	}
      
    fprintf(pub_key_file, "    </Bases>\n");
	fprintf(pub_key_file, "  </Elements>\n");
	fprintf(pub_key_file, "  <Features>\n");
    fprintf(pub_key_file, "    <Epoch length=\"432000\"/>\n");
	fprintf(pub_key_file, "  </Features>\n");
	fprintf(pub_key_file, "</IssuerPublicKey>\n");
	
	// Output the private key
	fprintf(priv_key_file, "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n");
	fprintf(priv_key_file, "<IssuerPrivateKey xmlns=\"http://www.zurich.ibm.com/security/idemix\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"http://www.zurich.ibm.com/security/idemix IssuerPrivateKey.xsd\">\n");
	fprintf(priv_key_file, "  <References>\n");
    fprintf(priv_key_file, "    <IssuerPublicKey>http://www.issuer.com/ipk.xml</IssuerPublicKey>\n");
	fprintf(priv_key_file, "  </References>\n");
	fprintf(priv_key_file, "  <Elements>\n");
    fprintf(priv_key_file, "    <n>"); fprintmpzdec(priv_key_file, pub_key->get_n()); fprintf(priv_key_file, "</n>\n");
    fprintf(priv_key_file, "    <p>"); fprintmpzdec(priv_key_file, priv_key->get_p()); fprintf(priv_key_file, "</p>\n");
    fprintf(priv_key_file, "    <pPrime>"); fprintmpzdec(priv_key_file, priv_key->get_p_prime()); fprintf(priv_key_file, "</pPrime>\n");
    fprintf(priv_key_file, "    <q>"); fprintmpzdec(priv_key_file, priv_key->get_q()); fprintf(priv_key_file, "</q>\n");
    fprintf(priv_key_file, "    <qPrime>"); fprintmpzdec(priv_key_file, priv_key->get_q_prime()); fprintf(priv_key_file, "</qPrime>\n");
	fprintf(priv_key_file, "  </Elements>\n");
	fprintf(priv_key_file, "</IssuerPrivateKey>\n");
	
	return 1;
}

int main(int argc, char* argv[])
{
	// Program parameters
	size_t bit_size = DEFAULT_BITSIZE;
	size_t num_attribs = 0;
	std::string pub_key_filename;
	std::string priv_key_filename;
	int c = 0;
	
	while ((c = getopt(argc, argv, "a:n:p:P:hv")) != -1)
	{
		switch (c)
		{
		case 'h':
			usage();
			return 0;
		case 'v':
			version();
			return 0;
		case 'a':
			num_attribs = atoi(optarg);
			break;
		case 'n':
			bit_size = atoi(optarg);
			break;
		case 'p':
			pub_key_filename = std::string(optarg);
			break;
		case 'P':
			priv_key_filename = std::string(optarg);
			break;
		}
	}
	
	if (num_attribs <= 0)
	{
		fprintf(stderr, "Missing argument -a; please specify a number of attributes\n");
		
		return -1;
	}
	
	FILE* pub_key_file = stdout;
	FILE* priv_key_file = stdout;
	
	if (!pub_key_filename.empty())
	{
		pub_key_file = fopen(pub_key_filename.c_str(), "w");
		
		if (pub_key_file == NULL)
		{
			fprintf(stderr, "Failed to open %s for writing\n", pub_key_filename.c_str());
			
			return -1;
		}
		
		printf("Writing public key to %s\n", pub_key_filename.c_str());
	}
	
	if (!priv_key_filename.empty())
	{
		priv_key_file = fopen(priv_key_filename.c_str(), "w");
		
		if (priv_key_file == NULL)
		{
			fprintf(stderr, "Failed to open %s for writing\n", priv_key_filename.c_str());
			
			return -1;
		}
		
		printf("Writing private key to %s\n", priv_key_filename.c_str());
	}
	
	generate_key_pair(pub_key_file, priv_key_file, num_attribs, bit_size);
	
	if (!pub_key_filename.empty()) fclose(pub_key_file);
	if (!priv_key_filename.empty()) fclose(priv_key_file);
	
	return 0;
}
