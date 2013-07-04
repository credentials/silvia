/* $Id: silvia_parameters.cpp 52 2013-07-02 13:16:24Z rijswijk $ */

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
 silvia_parameters.h

 System parameters
 *****************************************************************************/

#include "config.h"
#include "silvia_parameters.h"

// The one-and-only instance
/*static*/ std::auto_ptr<silvia_system_parameters> silvia_system_parameters::_i(NULL);

/*static*/ silvia_system_parameters* silvia_system_parameters::i()
{
	if (_i.get() == NULL)
	{
		_i = std::auto_ptr<silvia_system_parameters>(new silvia_system_parameters());
	}

	return _i.get();
}

silvia_system_parameters::silvia_system_parameters()
{
	reset();
}

void silvia_system_parameters::set_l_n(size_t l_n)
{
	this->l_n = l_n;
}

size_t silvia_system_parameters::get_l_n()
{
	return l_n;
}

void silvia_system_parameters::set_l_m(size_t l_m)
{
	this->l_m = l_m;
}

size_t silvia_system_parameters::get_l_m()
{
	return l_m;
}

void silvia_system_parameters::set_l_e(size_t l_e)
{
	this->l_e = l_e;
}

size_t silvia_system_parameters::get_l_e()
{
	return l_e;
}

void silvia_system_parameters::set_l_e_prime(size_t l_e_prime)
{
	this->l_e_prime = l_e_prime;
}

size_t silvia_system_parameters::get_l_e_prime()
{
	return l_e_prime;
}

void silvia_system_parameters::set_l_v(size_t l_v)
{
	this->l_v = l_v;
}

size_t silvia_system_parameters::get_l_v()
{
	return l_v;
}

void silvia_system_parameters::set_l_statzk(size_t l_statzk)
{
	this->l_statzk = l_statzk;
}

size_t silvia_system_parameters::get_l_statzk()
{
	return l_statzk;
}

void silvia_system_parameters::set_l_H(size_t l_H)
{
	this->l_H = l_H;
}

size_t silvia_system_parameters::get_l_H()
{
	return l_H;
}

void silvia_system_parameters::set_hash_type(std::string hash_type)
{
	this->hash_type = hash_type;
}
	
std::string silvia_system_parameters::get_hash_type()
{
	return hash_type;
}

void silvia_system_parameters::set_l_pt(size_t l_pt)
{
	this->l_pt = l_pt;
	this->rabin_miller_its = (l_pt / 2) + (l_pt % 2); // round up
}
	
size_t silvia_system_parameters::get_l_pt()
{
	return l_pt;
}
	
size_t silvia_system_parameters::get_rabin_miller_its()
{
	return rabin_miller_its;
}

void silvia_system_parameters::reset()
{
	// Initialise with default values
	l_n 				= 2048;
	l_m 				= 256;
	l_e 				= 597;
	l_e_prime 			= 120;
	l_v					= 2724;
	l_statzk			= 80;
	l_H					= 256;
	l_pt				= 80;
	rabin_miller_its	= 40;
	hash_type			= "sha256";
}
