/* $Id: silvia_asn1.cpp 50 2013-06-30 11:28:35Z rijswijk $ */

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
 silvia_asn1.cpp

 ASN.1 classes for simple ASN.1 encoding
 *****************************************************************************/

#include "config.h"
#include "silvia_asn1.h"
#include <stack>
#include <stdlib.h>

////////////////////////////////////////////////////////////////////////
// silvia_asn1_object implementation
////////////////////////////////////////////////////////////////////////

silvia_asn1_object::silvia_asn1_object()
{
}

std::vector<unsigned char> silvia_asn1_object::get_der_len_encoding()
{
	std::vector<unsigned char> len_enc;
	
	if (value.size() < 128)
	{
		// Simple encoding
		len_enc.push_back((unsigned char) value.size());
	}
	else
	{
		// Long encoding
		std::stack<unsigned char> len_bytes;
		
		size_t len = value.size();
		
		while (len > 0)
		{
			len_bytes.push((unsigned char) len & 0xff);
			len >>= 8;
		}
		
		len_enc.push_back((unsigned char) 0x80 + len_bytes.size());
		
		while (!len_bytes.empty())
		{
			len_enc.push_back(len_bytes.top());
			len_bytes.pop();
		}
	}
	
	return len_enc;
}

////////////////////////////////////////////////////////////////////////
// silvia_asn1_sequence implementation
////////////////////////////////////////////////////////////////////////

silvia_asn1_sequence::silvia_asn1_sequence()
{
}
	
void silvia_asn1_sequence::append(silvia_asn1_object* obj)
{
	objects.push_back(obj);
}
	
std::vector<unsigned char> silvia_asn1_sequence::get_der_encoding()
{
	// Clear current encoding
	value.clear();
	
	std::vector<unsigned char> der_enc;
	
	// Encode the number of objects in the sequence
	silvia_asn1_integer obj_count(objects.size());
	std::vector<unsigned char> obj_count_der = obj_count.get_der_encoding();
	
	value.insert(value.end(), obj_count_der.begin(), obj_count_der.end());
	
	// Append encodings of all the objects in the sequence
	for (std::vector<silvia_asn1_object*>::iterator i = objects.begin(); i != objects.end(); i++)
	{
		std::vector<unsigned char> obj_der = (*i)->get_der_encoding();
		
		value.insert(value.end(), obj_der.begin(), obj_der.end());
	}
	
	std::vector<unsigned char> seq_len_enc = get_der_len_encoding();
	
	der_enc.push_back(0x30);	// ASN.1: SEQUENCE
	der_enc.insert(der_enc.end(), seq_len_enc.begin(), seq_len_enc.end());
	der_enc.insert(der_enc.end(), value.begin(), value.end());
	
	return der_enc;
}
	
////////////////////////////////////////////////////////////////////////
// silvia_asn1_integer implementation
////////////////////////////////////////////////////////////////////////

silvia_asn1_integer::silvia_asn1_integer(mpz_class i)
{
	size_t count = 0;

	// Convert integer to big endian byte string
	unsigned char* mpz_bytes = (unsigned char*) mpz_export(NULL, &count, 1, sizeof(unsigned char), 1, 0, i.get_mpz_t());
	
	if (count == 0) return;
	
	// Strip leading zeroes
	size_t index = 0;
	
	while ((index < count) && (mpz_bytes[index] == 0x00)) index++;
	
	if (index == count)
	{
		free(mpz_bytes);
		return;
	}
	
	count -= index;
	
	// Prepend 0x00 if necessary, to make it unsigned
	if (mpz_bytes[index] >= 0x80)
	{
		value.resize(count + 1);
		value[0] = 0x00;
		memcpy(&value[1], &mpz_bytes[index], count);
	}
	else
	{
		value.resize(count);
		memcpy(&value[0], &mpz_bytes[index], count);
	}
	
	free(mpz_bytes);
}

silvia_asn1_integer::silvia_asn1_integer(std::vector<unsigned char> i)
{
	value.clear();
	
	if (i.size() == 0) return;
	
	// Strip leading zeroes
	size_t index = 0;
	size_t count = i.size();
	
	while ((index < count) && (i[index] == 0x00)) index++;
	
	if (index == count) return;
	
	// Prepend 0x00 if necessary, to make it unsigned
	if (i[index] >= 0x80)
	{
		value.push_back(0x00);
		value.insert(value.end(), i.begin() + index, i.end());
	}
	else
	{
		value.insert(value.end(), i.begin() + index, i.end());
	}
}

std::vector<unsigned char> silvia_asn1_integer::get_der_encoding()
{
	std::vector<unsigned char> der_enc;
	
	std::vector<unsigned char> len_enc = get_der_len_encoding();
	
	der_enc.push_back(0x02);	// ASN.1: INTEGER
	der_enc.insert(der_enc.end(), len_enc.begin(), len_enc.end());
	der_enc.insert(der_enc.end(), value.begin(), value.end());
	
	return der_enc;
}
