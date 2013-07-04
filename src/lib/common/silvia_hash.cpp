/* $Id: silvia_hash.cpp 50 2013-06-30 11:28:35Z rijswijk $ */

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
 silvia_hash.cpp

 Hash functions based on the OpenSSL EVP API
 *****************************************************************************/

#include "config.h"
#include "silvia_hash.h"
#include <vector>
#include <stack>

silvia_hash::silvia_hash(const std::string type)
{
	if (type == "sha1")
	{
		hash = (EVP_MD*) EVP_sha1();	
	}
	else if (type == "sha256")
	{
		hash = (EVP_MD*) EVP_sha256();
	}
	else if (type == "sha512")
	{
		hash = (EVP_MD*) EVP_sha512();
	}
	else
	{
		// TODO: throw an exception!
		return;
	}

	dirty = false;
}

silvia_hash::~silvia_hash()
{
	if (dirty) EVP_MD_CTX_cleanup(&hash_ctx);
}

void silvia_hash::init()
{
	EVP_DigestInit(&hash_ctx, hash);
	dirty = true;
}

void silvia_hash::update(const unsigned char* data, size_t size)
{
	EVP_DigestUpdate(&hash_ctx, (unsigned char*) data, size);
}

void silvia_hash::update(const std::vector<unsigned char> data)
{
	this->update(&data[0], data.size());
}

void silvia_hash::update(mpz_class data)
{
	size_t count = 0;

	// Output data as big endian byte string
	unsigned char* mpz_bytes = (unsigned char*) mpz_export(NULL, &count, 1, sizeof(unsigned char), 1, 0, data.get_mpz_t());
	
	this->update(mpz_bytes, count);
	
	free(mpz_bytes);
}

mpz_class silvia_hash::final()
{
	std::vector<unsigned char> hash_data;
	hash_data.resize(64); // enough to hold a SHA512 hash

	unsigned int out_len = 64;

	EVP_DigestFinal(&hash_ctx, &hash_data[0], &out_len);
	
	dirty = false;

	mpz_class rv;

	mpz_import(rv.get_mpz_t(), out_len, 1, sizeof(unsigned char), 1, 0, &hash_data[0]);

	return rv;
}

