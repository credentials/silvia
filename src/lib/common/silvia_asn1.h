/* $Id: silvia_asn1.h 50 2013-06-30 11:28:35Z rijswijk $ */

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
 silvia_asn1.h

 ASN.1 classes for simple ASN.1 encoding
 *****************************************************************************/

#ifndef _SILVIA_ASN1_H
#define _SILVIA_ASN1_H

#include "config.h"
#include <gmpxx.h>
#include <string>
#include <vector>

/**
 * Generic ASN.1 object class
 */
class silvia_asn1_object
{
public:
	/**
	 * Get the DER encoding
	 * @return the ASN.1 DER encoding of the object
	 */
	virtual std::vector<unsigned char> get_der_encoding() = 0;

protected:
	/**
	 * Constructor
	 */
	silvia_asn1_object();
	
	/**
	 * Utility function constructs the ASN.1 DER encoding of the
	 * length of the value
	 */
	std::vector<unsigned char> get_der_len_encoding();
	
	// Value
	std::vector<unsigned char> value;
};

/**
 * ASN.1 sequence object class
 */
class silvia_asn1_sequence : public silvia_asn1_object
{
public:
	/**
	 * Constructor
	 */
	silvia_asn1_sequence();
	
	/**
	 * Append an ASN.1 object to the sequence
	 * @param obj the object to append to the sequence
	 */
	void append(silvia_asn1_object* obj);
	
	/**
	 * Get the DER encoding
	 * @return the ASN.1 DER encoding of the sequence
	 */
	virtual std::vector<unsigned char> get_der_encoding();
	
private:
	// The objects in the sequence
	std::vector<silvia_asn1_object*> objects;
};

/**
 * ASN.1 integer object class
 */
class silvia_asn1_integer : public silvia_asn1_object
{
public:
	/**
	 * Constructor
	 * @param i the integer
	 */
	silvia_asn1_integer(mpz_class i);
	
	/**
	 * Constructor
	 * @param i the integer byte string
	 */
	silvia_asn1_integer(std::vector<unsigned char> i);
	
	/**
	 * Get the DER encoding
	 * @return the ASN.1 DER encoding of the integer
	 */
	virtual std::vector<unsigned char> get_der_encoding();
};

#endif // !_SILVIA_ASN1_H

