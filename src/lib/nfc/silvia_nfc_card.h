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
 silvia_nfc_card.h

 Smart card communication classes
 *****************************************************************************/
 
#include "config.h"
#include "silvia_bytestring.h"
#include "silvia_card_channel.h"
#include <nfc/nfc.h>
#include <memory>
#include <string>
 
#ifndef _SILVIA_NFC_CARD_H
#define _SILVIA_NFC_CARD_H
 
/**
 * Card class
 */
  
class silvia_nfc_card : public silvia_card_channel
{
public:
	/**
	 * Constructor
	 * @param device the NFC device
	 * @param reader_name the card reader name
	 */
	silvia_nfc_card(nfc_device* device, nfc_target target, std::string reader_name);
	
	/**
	 * Destructor
	 * Will disconnect from the card if a connection still exists
	 */
	~silvia_nfc_card();
	
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
	
	/**
	 * Get the card reader name in which the card resides
	 * @return the card reader name of the reader containing the card
	 */
	virtual std::string get_reader_name();

private:
	// The card connection status
	bool connected;
	
	// The NFC device and target
	nfc_device* device;
	nfc_target target;
	
	// The card reader name
	std::string reader_name;
};
 
/**
 * Card monitor class
 */
class silvia_nfc_card_monitor
{
public:
	/**
	 * Get the one-and-only instance of the card monitor object
	 * @return the one-and-only instance of the card monitor object
	 */
	static silvia_nfc_card_monitor* i();
	
	/**
	 * Wait for a new card to be inserted
	 * @param card returns a card object for the inserted card
	 * @return true if a card was successfully detected and a new card
	 *              object was created
	 */
	bool wait_for_card(silvia_nfc_card** card);
	
	/**
	 * Destructor
	 */
	~silvia_nfc_card_monitor();
	
private:
	// Constructor
	silvia_nfc_card_monitor();
	
	// State
	nfc_context* context;
	nfc_device* device;

	// The one-and-only instance
	static std::auto_ptr<silvia_nfc_card_monitor> _i;	
};
 
#endif // !_SILVIA_NFC_CARD_H
