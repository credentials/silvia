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
 silvia_bytestring.cpp

 A string class for byte strings
 *****************************************************************************/

#include <algorithm>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "silvia_bytestring.h"
#include "silvia_macros.h"

// Constructors
bytestring::bytestring()
{
}

bytestring::bytestring(const unsigned char* bytes, const size_t bytesLen)
{
	byteString.resize(bytesLen);

	memcpy(&byteString[0], bytes, bytesLen);
}

bytestring::bytestring(const char* hexString)
{
	std::string hex = std::string(hexString);

	if (hex.size() % 2 != 0)
	{
		hex = "0" + hex;
	}

	for (size_t i = 0; i < hex.size(); i += 2)
	{
		std::string byteStr;
		byteStr += hex[i];
		byteStr += hex[i+1];

		unsigned char byteVal = (unsigned char) strtoul(byteStr.c_str(), NULL, 16);

		this->operator+=(byteVal);
	}
}

bytestring::bytestring(const unsigned long longValue)
{
	unsigned long setValue = longValue;

	// Convert the value to a big-endian byte string; N.B.: this code assumes that unsigned long
	// values are stored as a 64-bit value, which is a safe assumption on modern systems. It will
	// also properly handle a 32-bit value and will simply store 4 zeroes at the front of the
	// string. If at some point in time we get 128-bit architectures, the top 8 bytes of the value
	// will be discarded... (but hey, 640K is enough for everybody, right?)
	//
	// The reason for coding it this way is that implementations of SoftHSM will maintain
	// binary compatibility between eachothers background storage (i.e. a 32-bit SoftHSM version can
	// read the storage of a 64-bit version and vice versa under the assumption that the stored
	// values never exceed 32-bits, which is likely since these values are only used to encode
	// byte string lengths)
	unsigned char byteStrIn[8];
	
	for (size_t i = 0; i < 8; i++)
	{
		byteStrIn[7-i] = (unsigned char) (setValue & 0xFF);
		setValue >>= 8;
	}

	byteString.resize(8);
	memcpy(&byteString[0], byteStrIn, 8);
}

bytestring::bytestring(const bytestring& in)
{
	this->byteString = in.byteString;
}

bytestring::bytestring(const mpz_class& mpz_val)
{
	size_t count;
	
	unsigned char* byte_val = (unsigned char*) mpz_export(NULL, &count, 1, sizeof(unsigned char), 1, 0, _Z(mpz_val));
	
	byteString.resize(count);
	memcpy(&byteString[0], byte_val, count);
	
	free(byte_val);
}

// Append data
bytestring& bytestring::operator+=(const bytestring& append)
{
	size_t curLen = byteString.size();
	size_t toAdd = append.byteString.size();
	size_t newLen = curLen + toAdd;

	byteString.resize(newLen);

	memcpy(&byteString[curLen], &append.byteString[0], toAdd);

	return *this;
}

bytestring& bytestring::operator+=(const unsigned char byte)
{
	byteString.push_back(byte);

	return *this;
}

// XORing
bytestring& bytestring::operator^=(const bytestring& rhs)
{
	size_t xorLen = std::min(this->size(), rhs.size());

	for (size_t i = 0; i < xorLen; i++)
	{
		byteString[i] ^= rhs.const_byte_str()[i];
	}

	return *this;
}

// Return a substring
bytestring bytestring::substr(const size_t start, const size_t len /* = SIZE_T_MAX */) const
{
	size_t retLen = std::min(len, byteString.size() - start);

	if (start >= byteString.size())
	{
		return bytestring();
	}
	else
	{
		return bytestring(&byteString[start], retLen);
	}
}

// Add data
bytestring operator+(const bytestring& lhs, const bytestring& rhs)
{
	bytestring rv = lhs;
	rv += rhs;

	return rv;
}

bytestring operator+(const unsigned char lhs, const bytestring& rhs)
{
	bytestring rv(&lhs, 1);
	rv += rhs;

	return rv;
}

bytestring operator+(const bytestring& lhs, const unsigned char rhs)
{
	bytestring rv = lhs;
	rv += rhs;

	return rv;
}

// Array operator
unsigned char& bytestring::operator[](size_t pos)
{
	return byteString[pos];
}

// Return the byte string data
unsigned char* bytestring::byte_str()
{
	return &byteString[0];
}

// Return as GNU MP integer
mpz_class bytestring::mpz_val()
{
	mpz_class rv;
	
	mpz_import(_Z(rv), byteString.size(), 1, sizeof(unsigned char), 1, 0, &byteString[0]);
	
	return rv;
}

// Return the const byte string
const unsigned char* bytestring::const_byte_str() const
{
	return (const unsigned char*) &byteString[0];
}

// Return a hexadecimal character representation of the string
std::string bytestring::hex_str() const
{
	std::string rv;
	char hex[3];

	for (size_t i = 0; i < byteString.size(); i++)
	{
		sprintf(hex, "%02X", byteString[i]);

		rv += hex;
	}

	return rv;
}

// Split of the specified part of the string as a separate byte string
bytestring bytestring::split(size_t len)
{
	bytestring rv = substr(0, len);

	size_t newSize = (byteString.size() > len) ? (byteString.size() - len) : 0;

	if (newSize > 0)
	{
		for (size_t i = 0; i < newSize; i++)
		{
			byteString[i] = byteString[i + len];
		}
	}

	byteString.resize(newSize);

	return rv;
}

// The size of the byte string in bits
size_t bytestring::bits() const
{
	size_t bits = byteString.size() * 8;

	if (bits == 0) return 0;

	for (size_t i = 0; i < byteString.size(); i++)
	{
		unsigned char byte = byteString[i];

		for (unsigned char mask = 0x80; mask > 0; mask >>= 1)
		{
			if ((byte & mask) == 0)
			{
				bits--;
			}
			else
			{
				return bits;
			}
		}
	}

	return bits;
}

// The size of the byte string in bytes
size_t bytestring::size() const
{
	return byteString.size();
}

void bytestring::resize(const size_t newSize)
{
	byteString.resize(newSize);
}

void bytestring::wipe(const size_t newSize /* = 0 */)
{
	this->resize(newSize);

	memset(&byteString[0], 0x00, byteString.size());
}

// Comparison
bool bytestring::operator==(const bytestring& compareTo) const
{
	if (compareTo.size() != this->size())
	{
		return false;
	}

	return (memcmp(&byteString[0], &compareTo.byteString[0], this->size()) == 0);
}

bool bytestring::operator!=(const bytestring& compareTo) const
{
	if (compareTo.size() != this->size())
	{
		return true;
	}

	return (memcmp(&byteString[0], &compareTo.byteString[0], this->size()) != 0);
}

// XOR data
bytestring operator^(const bytestring& lhs, const bytestring& rhs)
{
	size_t xorLen = std::min(lhs.size(), rhs.size());
	bytestring rv;

	for (size_t i = 0; i < xorLen; i++)
	{
		rv += lhs.const_byte_str()[i] ^ rhs.const_byte_str()[i];
	}

	return rv;
}
