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
 silvia_verifier_spec.h

 Verifier specification
 *****************************************************************************/

#include "config.h"
#include <gmpxx.h>
#include "silvia_types.h"
#include "silvia_verifier_spec.h"
#include <vector>
#include <assert.h>

silvia_verifier_specification::silvia_verifier_specification
(
	std::string verifier_name,
	std::string short_msg,
	unsigned int verifier_id,
	unsigned short credential_id,
	std::vector<std::string> attribute_names,
	std::vector<bool> D
)
{
	this->verifier_name = verifier_name;
	this->short_msg = short_msg;
	this->verifier_id = verifier_id;
	this->credential_id = credential_id;
	this->attribute_names = attribute_names;
	this->D = D;
}
	
std::string silvia_verifier_specification::get_verifier_name()
{
	return verifier_name;
}

std::string silvia_verifier_specification::get_short_msg()
{
	return short_msg;
}

unsigned int silvia_verifier_specification::get_verifier_id()
{
	return verifier_id;
}

unsigned short silvia_verifier_specification::get_credential_id()
{
	return credential_id;
}

std::vector<std::string>& silvia_verifier_specification::get_attribute_names()
{
	return attribute_names;
}

std::vector<bool>& silvia_verifier_specification::get_D()
{
	return D;
}
