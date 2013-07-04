/* $Id: silvia_hash.h 50 2013-06-30 11:28:35Z rijswijk $ */

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
 silvia_hash.h

 Hash functions based on the OpenSSL EVP API
 *****************************************************************************/

#ifndef _SILVIA_HASH_H
#define _SILVIA_HASH_H

#include "config.h"
#include <gmpxx.h>
#include <openssl/evp.h>
#include <string>
#include <vector>

/**
 * Hash class
 */
class silvia_hash
{
public:
	/**
	 * Constructor
	 * @param type the hash type; can be "sha1", "sha256" or "sha512"
	 */
	silvia_hash(const std::string type);

	/**
	 * Destructor
	 */
	~silvia_hash();

	/**
	 * Initialise hashing
	 */
	void init();

	/**
	 * Hash the supplied data
	 * @param data the data to hash
	 * @param size the size of the data to hash
	 */
	void update(const unsigned char* data, size_t size);
	
	/**
	 * Hash the supplied data
	 * @param data the data to hash
	 */
	void update(const std::vector<unsigned char> data);

	/**
	 * Hash the supplied data
	 * @param data the data to hash
	 */
	void update(mpz_class data);

	/**
	 * Finish hashing
	 */
	mpz_class final();

private:
	EVP_MD_CTX hash_ctx;
	EVP_MD* hash;
	bool dirty;
};

#endif // !_SILVIA_HASH_H

