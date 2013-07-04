/* $Id: silvia_issuer_keygen.h 49 2013-06-25 14:35:03Z rijswijk $ */

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
 silvia_issuer_keygen.h

 Issuer key generation
 *****************************************************************************/

#ifndef _SILVIA_ISSUER_KEYGEN_H
#define _SILVIA_ISSUER_KEYGEN_H

#include "config.h"
#include <gmpxx.h>
#include "silvia_types.h"
#include <memory>

/**
 * Key factory
 */
class silvia_issuer_keyfactory
{
public:
	/**
	 * Get the one-and-only instance of the key factory object
	 * @return the one-and-only instance of the key factory object
	 */
	static silvia_issuer_keyfactory* i();

	/**
	 * Generate a new issuer key-pair
	 * @param max_attr the maximum number of attributes to support
	 * @param pubkey the public key object
	 * @param privkey the private key object
	 */
	void generate_keypair
	(
		size_t max_attr,
		silvia_pub_key** pubkey,
		silvia_priv_key** privkey
	);

private:
	// Constructor
	silvia_issuer_keyfactory();

	// The one-and-only instance
	static std::auto_ptr<silvia_issuer_keyfactory> _i;
};

#endif // !_SILVIA_ISSUER_KEYGEN_H

