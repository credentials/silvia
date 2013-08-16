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
 silvia_pcsc_card.cpp

 Smart card communication classes
 *****************************************************************************/
 
#include "config.h"
#include "silvia_pcsc_card.h"
#include "silvia_macros.h"
#include <PCSC/winscard.h>
#include <assert.h>
#include <string.h>
#include <vector>
#include <stdio.h>

////////////////////////////////////////////////////////////////////////
// Card class
////////////////////////////////////////////////////////////////////////
  
silvia_pcsc_card::silvia_pcsc_card(SCARDHANDLE card_handle, DWORD protocol, std::string reader_name)
{
	this->card_handle = card_handle;
	this->protocol = protocol;
	this->reader_name = reader_name;
	
	connected = true;
	
	status();
}
	
silvia_pcsc_card::~silvia_pcsc_card()
{
	if (connected)
	{
		SCardDisconnect(card_handle, SCARD_UNPOWER_CARD);
	}
}

int silvia_pcsc_card::get_type()
{
	return SILVIA_CHANNEL_PCSC;
}
	
bool silvia_pcsc_card::status()
{
	if (!connected) return false;
	
	DWORD active_protocol;
	DWORD state;
	DWORD atr_len = MAX_ATR_SIZE;
	DWORD reader_len = 0;
	BYTE atr[MAX_ATR_SIZE];
	
	LONG rv = SCardStatus(card_handle, NULL, &reader_len, &state, &active_protocol, atr, &atr_len);
	
	connected = (rv == SCARD_S_SUCCESS) && (FLAG_SET(state, SCARD_PRESENT));
	
	if (!connected)
	{
		SCardDisconnect(card_handle, SCARD_UNPOWER_CARD);
	}
	
	return connected;
}
	
bool silvia_pcsc_card::transmit(bytestring APDU, bytestring& data, unsigned short& sw)
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

bool silvia_pcsc_card::transmit(bytestring APDU, bytestring& data_sw)
{
	if (!connected) return false;
	
	data_sw.resize(65536);
	DWORD out_len = 65536;
	SCARD_IO_REQUEST recv_req;
		
	LONG rv = SCardTransmit(
		card_handle, 
		protocol == SCARD_PROTOCOL_T0 ? SCARD_PCI_T0 : SCARD_PCI_T1, 
		APDU.byte_str(), 
		APDU.size(), 
		&recv_req,
		data_sw.byte_str(),
		&out_len);
		
	if (rv != SCARD_S_SUCCESS)
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

std::string silvia_pcsc_card::get_reader_name()
{
	return reader_name;
}

////////////////////////////////////////////////////////////////////////
// Card monitor class
////////////////////////////////////////////////////////////////////////

// Initialise the one-and-only instance
/*static*/ std::auto_ptr<silvia_pcsc_card_monitor> silvia_pcsc_card_monitor::_i(NULL);

/*static*/ silvia_pcsc_card_monitor* silvia_pcsc_card_monitor::i()
{
	if (_i.get() == NULL)
	{
		_i = std::auto_ptr<silvia_pcsc_card_monitor>(new silvia_pcsc_card_monitor());
	}

	return _i.get();
}
	
bool silvia_pcsc_card_monitor::wait_for_card(silvia_pcsc_card** card)
{
	assert(card != NULL);
	
	// First, find which card readers are available
	LPTSTR readers;
	LPTSTR readers_orig;
	DWORD reader_len;
	
	LONG rv = SCardListReaders(pcsc_context, NULL, NULL, &reader_len);
	
	if ((rv != SCARD_S_SUCCESS) || (reader_len == 0))
	{
		return false;
	}
	
	readers_orig = readers = (LPTSTR) malloc(reader_len * sizeof(char));
	
	rv = SCardListReaders(pcsc_context, NULL, readers, &reader_len);
	
	if (rv != SCARD_S_SUCCESS)
	{
		free(readers_orig);
		
		return false;
	}
	
	// Add readers to availability structure
	std::vector<SCARD_READERSTATE> reader_states;
	
	while (reader_len > 1)
	{
		size_t len = strlen(readers);
		
		SCARD_READERSTATE reader_state;
		
		reader_state.szReader = readers;
		reader_state.pvUserData = NULL;
		reader_state.dwCurrentState = SCARD_STATE_UNAWARE;
		reader_state.dwEventState = SCARD_STATE_UNAWARE;
		reader_state.cbAtr = MAX_ATR_SIZE;
		
		reader_states.push_back(reader_state);
		
		reader_len -= len + 1;
		readers += len + 1;
	}
	
	rv = SCardGetStatusChange(pcsc_context, INFINITE, &reader_states[0], reader_states.size());
	
	if (rv != SCARD_S_SUCCESS)
	{
		free(readers_orig);
		
		return false;
	}
	
	while (true)
	{
		for (std::vector<SCARD_READERSTATE>::iterator i = reader_states.begin(); i != reader_states.end(); i++)
		{
			if (FLAG_SET(i->dwEventState, SCARD_STATE_PRESENT))
			{
				// Attempt to connect to this particular card
				DWORD active_protocol;
				SCARDHANDLE card_handle;
				
				rv = SCardConnect(pcsc_context, i->szReader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &card_handle, &active_protocol);
				
				if (rv == SCARD_S_SUCCESS)
				{
					*card = new silvia_pcsc_card(card_handle, active_protocol, i->szReader);
					
					free(readers_orig);
					
					return true;
				}
			}
			
			i->dwCurrentState = i->dwEventState;
		}
		
		rv = SCardGetStatusChange(pcsc_context, INFINITE, &reader_states[0], reader_states.size());
		
		if (rv != SCARD_S_SUCCESS)
		{
			break;
		}
	}
	
	free(readers_orig);
	
	return false;
}
	
silvia_pcsc_card_monitor::silvia_pcsc_card_monitor()
{
	// FIXME: do something with the return value of this call rather
	//        than asserting on failure
	assert(SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &pcsc_context) == SCARD_S_SUCCESS);
}

silvia_pcsc_card_monitor::~silvia_pcsc_card_monitor()
{
	SCardReleaseContext(pcsc_context);
}
