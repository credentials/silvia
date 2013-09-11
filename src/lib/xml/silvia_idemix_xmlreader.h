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
 silvia_idemix_xmlreader.h

 XML reader that will read and parse the XML file types that are relevant for
 Silvia and the IRMA project
 *****************************************************************************/

#ifndef _SILVIA_IDEMIX_XMLREADER_H
#define _SILVIA_IDEMIX_XMLREADER_H

#include <gmpxx.h>
#include "silvia_types.h"
#include <vector>
#include <memory>

/**
 * Idemix XML reader class
 */
class silvia_idemix_xmlreader
{
public:
	/**
	 * Get the one-and-only instance of the Idemix XML reader object
	 * @return the one-and-only instance of the Idemix XML reader object
	 */
	static silvia_idemix_xmlreader* i();
	
	/**
	 * Retrieve a public key object from an Idemix public key XML file
	 * @param file_name the name of the XML file
	 * @return a new public key object or NULL if reading/parsing failed
	 */
	silvia_pub_key* read_idemix_pubkey(const std::string file_name);
	
	/**
	 * Retrieve a private key object from an Idemix public key XML file
	 * @param file_name the name of the XML file
	 * @return a new private key object or NULL if reading/parsing failed
	 */
	silvia_priv_key* read_idemix_privkey(const std::string file_name);
	
private:
	// The one-and-only instance
	static std::auto_ptr<silvia_idemix_xmlreader> _i;
};

#endif // !_SILVIA_IDEMIX_XMLREADER_H

