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
 silvia_stdio_card.h

 POSIX StdIO communication classes
 *****************************************************************************/
 
#include "silvia_bytestring.h"
#include "silvia_card_channel.h"
#include <iostream>
#include <memory>
#include <string>
 
#ifndef _SILVIA_STDIO_CARD_H
#define _SILVIA_STDIO_CARD_H
 
/**
 * Card class
 */
  
class silvia_stdio_card : public silvia_card_channel
{
public:
	/**
	 * Constructor
     * @param to_card the descriptor for communication to the card
     * @param from_card the descriptor for communication from the card
	 */
	silvia_stdio_card();
	
	/**
	 * Destructor
	 * Will give the command to disconnect from the card
	 */
	~silvia_stdio_card();
	
	/**
	 * Get the channel type
	 * @return the channel type
	 */
	virtual int get_type();
	
	/**
	 * Get the connection status
	 * @return the connection status (true = connected)
	 */
	virtual bool status();
	
	/**
	 * Transmit an APDU and receive return data
	 * @param apdu The APDU to transmit
	 * @param data The return data
	 * @param sw The return status word
	 * @return true if the APDU exchange completed successfully
	 */
	virtual bool transmit(bytestring APDU, bytestring& data, unsigned short& sw);
	
	/**
	 * Transmit an APDU and receive return data
	 * @param apdu The APDU to transmit
	 * @param data_sw The return data including the status word
	 * @return true if the APDU exchange completed successfully
	 */
	virtual bool transmit(bytestring APDU, bytestring& data_sw);

    virtual std::string get_reader_name();
	
private:
	// The card connection status
	bool connected;
};
 
#endif // !_SILVIA_STDIO_CARD_H
