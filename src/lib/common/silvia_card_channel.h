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
 silvia_card_channel.h

 Abstract base class for card channels
 *****************************************************************************/

#ifndef _SILVIA_CARD_CHANNEL_H
#define _SILVIA_CARD_CHANNEL_H

#include "config.h"
#include <string>
#include "silvia_bytestring.h"

/**
 * Card channel interface
 */
 
#define SILVIA_CHANNEL_PCSC				0x01	// Local PC/SC reader through libpcsclite
#define SILVIA_CHANNEL_NFC				0x02	// Local NFC reader through libnfc
#define SILVIA_CHANNEL_PROXY			0x03	// Card proxy
 
class silvia_card_channel
{
public:
	/**
	 * Get the channel type
	 * @return the channel type
	 */
	virtual int get_type() = 0;
	
	/**
	 * Get the connection status
	 * @return true if the connection is up
	 */
	virtual bool status() = 0;
	
	/**
	 * Transmit an APDU and receive return data
	 * @param apdu The APDU to transmit
	 * @param data The return data
	 * @param sw The return status word
	 * @return true if the APDU exchange completed successfully
	 */
	virtual bool transmit(bytestring APDU, bytestring& data, unsigned short& sw) = 0;
	
	/**
	 * Transmit an APDU and receive return data
	 * @param apdu The APDU to transmit
	 * @param data_sw The return data including the status word
	 * @return true if the APDU exchange completed successfully
	 */
	virtual bool transmit(bytestring APDU, bytestring& data_sw) = 0;
	
	/**
	 * Get the card reader name in which the card resides
	 * @return the card reader name of the reader containing the card
	 */
	virtual std::string get_reader_name() = 0;

private:
};

#endif // !_SILVIA_CARD_CHANNEL_H

