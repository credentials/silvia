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
#include "silvia_apdu.h"
#include "silvia_macros.h"
#include <assert.h>
#include <string.h>
#include <vector>
#include <stdio.h>

silvia_apdu::silvia_apdu(unsigned char CLA, unsigned char INS, unsigned char P1, unsigned char P2)
{
	this->CLA = CLA;
	this->INS = INS;
	this->P1 = P1;
	this->P2 = P2;
	this->LE = -1;
}
	
void silvia_apdu::append_data(const bytestring& data)
{
	this->data += data;
}
	
void silvia_apdu::set_le(int LE)
{
	if (LE < 255)
	{
		this->LE = LE;
	}
	else if (LE == 256)
	{
		this->LE = 256;
	}
	else
	{
		this->LE = -1;
	}
}
	
bytestring silvia_apdu::get_apdu()
{
	bytestring the_apdu;
	
	the_apdu += CLA;
	the_apdu += INS;
	the_apdu += P1;
	the_apdu += P2;
	
	if (data.size() > 0)
	{
		the_apdu += (unsigned char) data.size();
		the_apdu += data;
	}
	
	if (LE >= 0)
	{
		the_apdu += LE;
	}
	
	return the_apdu;
}
