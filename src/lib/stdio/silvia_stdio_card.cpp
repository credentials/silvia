/* $Id$ */

/*
 * Copyright (c) 2014 Patrick Uiterwijk
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
 silvia_stdio_card.cpp

 StdIO communication classes
 *****************************************************************************/
 
#include "config.h"
#include "silvia_stdio_card.h"
#include "silvia_macros.h"
#include <assert.h>
#include <string.h>
#include <vector>
#include <stdio.h>

////////////////////////////////////////////////////////////////////////
// Card class
////////////////////////////////////////////////////////////////////////
  
silvia_stdio_card::silvia_stdio_card()
{
	status();
}
	
silvia_stdio_card::~silvia_stdio_card()
{
}

int silvia_stdio_card::get_type()
{
	return SILVIA_CHANNEL_STDIO;
}
	
bool silvia_stdio_card::status()
{
    // Assume to be always connected
    return true;
}
	
bool silvia_stdio_card::transmit(bytestring APDU, bytestring& data, unsigned short& sw)
{
	if (!transmit(APDU, data))
	{
		return false;
	}
	
	sw = data[data.size() - 2] << 8;
	sw += data[data.size() - 1];
	
	data.resize(data.size() - 2);
	
	return true;
}

bool silvia_stdio_card::transmit(bytestring APDU, bytestring& data_sw)
{
    std::cout << "request " << APDU.hex_str() << std::endl << std::flush;

    std::string response_type;
    std::cin >> response_type;
    if(response_type.compare("response") != 0)
        return false;

    std::string response;
    std::cin >> response;

    data_sw += response.c_str();
	
	if (data_sw.size() < 2)
	{
		return false;
	}
	
	return true;
}

std::string silvia_stdio_card::get_reader_name()
{
	return "STDIO";
}
