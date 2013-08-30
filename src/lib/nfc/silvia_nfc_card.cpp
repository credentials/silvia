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
 silvia_nfc_card.cpp

 Smart card communication classes
 *****************************************************************************/
 
#include "config.h"
#include "silvia_nfc_card.h"
#include "silvia_macros.h"
#include <assert.h>
#include <string.h>
#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define NFC_TIMEOUT 5000

////////////////////////////////////////////////////////////////////////
// Card class
////////////////////////////////////////////////////////////////////////
  
silvia_nfc_card::silvia_nfc_card(nfc_device* device, nfc_target target, std::string reader_name)
{
	this->device = device;
	this->target = target;
	
	connected = true;
	
	status();
}
	
silvia_nfc_card::~silvia_nfc_card()
{
}

int silvia_nfc_card::get_type()
{
	return SILVIA_CHANNEL_NFC;
}
	
bool silvia_nfc_card::status()
{
	if (!connected) return false;
	
	if (nfc_initiator_target_is_present(device, &target) != 0)
	{
		connected = false;
	}
	
	return connected;
}
	
bool silvia_nfc_card::transmit(bytestring APDU, bytestring& data, unsigned short& sw)
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

bool silvia_nfc_card::transmit(bytestring APDU, bytestring& data_sw)
{
	if (!connected) return false;
	
	data_sw.resize(65536);
	
	int out_len = nfc_initiator_transceive_bytes(device, APDU.byte_str(), APDU.size(), data_sw.byte_str(), data_sw.size(), 0);

	if (out_len < 2)
	{
		return false;
	}
	
	data_sw.resize(out_len);
	
	if (data_sw.size() < 2)
	{
		return false;
	}
	
	return true;
}

std::string silvia_nfc_card::get_reader_name()
{
	return reader_name;
}

////////////////////////////////////////////////////////////////////////
// Card monitor class
////////////////////////////////////////////////////////////////////////

// Initialise the one-and-only instance
/*static*/ std::auto_ptr<silvia_nfc_card_monitor> silvia_nfc_card_monitor::_i(NULL);

/*static*/ silvia_nfc_card_monitor* silvia_nfc_card_monitor::i()
{
	if (_i.get() == NULL)
	{
		_i = std::auto_ptr<silvia_nfc_card_monitor>(new silvia_nfc_card_monitor());
	}

	return _i.get();
}
	
bool silvia_nfc_card_monitor::wait_for_card(silvia_nfc_card** card)
{
	assert(card != NULL);
	
	if (device == NULL)
	{
		device = nfc_open(context, NULL);
	
		if (device == NULL)
		{
			return false;
		}
		
		nfc_initiator_init(device);
	}
	
	// CAVEAT: only tested with PN533
	const nfc_modulation modulation = { NMT_ISO14443A, NBR_106 };
	
	// Poll for a card
	int rv = 0;
	nfc_target target;
	
	while ((rv = nfc_initiator_select_passive_target(device, modulation, NULL, 0, &target)) == 0)
	{
		usleep(10000);
	}
	
	if (rv < 0)
	{
		return false;
	}
	
	*card = new silvia_nfc_card(device, target, "NFC reader");
	
	return true;
}
	
silvia_nfc_card_monitor::silvia_nfc_card_monitor()
{
	nfc_init(&context);
	device = nfc_open(context, NULL);
	
	if (device != NULL)
	{
		nfc_initiator_init(device);
	}
}

silvia_nfc_card_monitor::~silvia_nfc_card_monitor()
{
	nfc_close(device);
	nfc_exit(context);
}
