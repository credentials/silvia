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
 silvia_apdu.h

 APDU construction class
 *****************************************************************************/
 
#include "config.h"
#include "silvia_bytestring.h"
#include <memory>
#include <string>
 
#ifndef _SILVIA_APDU_H
#define _SILVIA_APDU_H
 
/**
 * APDU class
 */
 
class silvia_apdu
{
public:
	/**
	 * Constructor
	 * @param CLA APDU class byte
	 * @param INS APDU instruction byte
	 * @param P1 APDU parameter 1
	 * @param P2 APDU parameter 2
	 */
	silvia_apdu(unsigned char CLA, unsigned char INS, unsigned char P1, unsigned char P2);
	
	/**
	 * Append data
	 */
	void append_data(const bytestring& data);
	
	/**
	 * Set expected return length
	 * @param LE the expected return length (1-256)
	 */
	void set_le(int LE);
	
	/**
	 * Return byte string of the APDU
	 * @return a byte string of the whole APDU
	 */
	bytestring get_apdu();

private:
	// APDU values
	unsigned char CLA;
	unsigned char INS;
	unsigned char P1;
	unsigned char P2;
	int LE;
	
	bytestring data;
};
 
#endif // !_SILVIA_APDU_H
