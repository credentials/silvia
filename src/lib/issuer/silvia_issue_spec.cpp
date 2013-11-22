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
 silvia_issue_spec.cpp

 Issuing specification for a specific credential
 *****************************************************************************/

#include "config.h"
#include "silvia_issue_spec.h"

silvia_issue_specification::silvia_issue_specification
(
	std::string credential_name,
	std::string issuer_name,
	unsigned short credential_id,
	int expires,
	std::vector<silvia_attribute*> attributes
)
{
	this->credential_name = credential_name;
	this->issuer_name = issuer_name;
	this->credential_id = credential_id;
	this->expires = expires;
	this->attributes = attributes;
}

silvia_issue_specification::~silvia_issue_specification()
{
	for (std::vector<silvia_attribute*>::iterator i = attributes.begin(); i != attributes.end(); i++)
	{
		delete *i;
	}
}

std::string silvia_issue_specification::get_credential_name()
{
	return credential_name;
}

std::string silvia_issue_specification::get_issuer_name()
{
	return issuer_name;
}

unsigned short silvia_issue_specification::get_credential_id()
{
	return credential_id;
}

int silvia_issue_specification::get_expires()
{
	return expires;
}

std::vector<silvia_attribute*>& silvia_issue_specification::get_attributes()
{
	return attributes;
}

