/* $Id: silvia_types.cpp 52 2013-07-02 13:16:24Z rijswijk $ */

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
 silvia_types.cpp

 Generic type class implementations
 *****************************************************************************/

#include "config.h"
#include "silvia_types.h"
#include "silvia_hash.h"
#include "silvia_macros.h"
#include "silvia_parameters.h"

////////////////////////////////////////////////////////////////////////////////
// Issuer public key implementation
////////////////////////////////////////////////////////////////////////////////

silvia_pub_key::silvia_pub_key(mpz_class n, mpz_class S, mpz_class Z, std::vector<mpz_class> R)
{
	this->n = n;
	this->S = S;
	this->Z = Z;
	this->R = R;
}

silvia_pub_key::~silvia_pub_key()
{
}

mpz_class& silvia_pub_key::get_n()
{
	return n;
}

mpz_class& silvia_pub_key::get_S()
{
	return S;
}

mpz_class& silvia_pub_key::get_Z()
{
	return Z;
}
	
std::vector<mpz_class>& silvia_pub_key::get_R()
{
	return R;
}

////////////////////////////////////////////////////////////////////////////////
// Issuer private key implementation
////////////////////////////////////////////////////////////////////////////////

silvia_priv_key::silvia_priv_key(mpz_class p, mpz_class q)
{
	this->p = p;
	this->q = q;

	// Compute p' and q'
	p_prime = p - 1;
	mpz_divexact_ui(p_prime.get_mpz_t(), p_prime.get_mpz_t(), 2);

	q_prime = q - 1;
	mpz_divexact_ui(q_prime.get_mpz_t(), q_prime.get_mpz_t(), 2);
	
	// Compute n'
	n_prime = p_prime * q_prime;
}

silvia_priv_key::~silvia_priv_key()
{
}

mpz_class& silvia_priv_key::get_p()
{
	return p;
}

mpz_class& silvia_priv_key::get_q()
{
	return q;
}

mpz_class& silvia_priv_key::get_p_prime()
{
	return p_prime;
}

mpz_class& silvia_priv_key::get_q_prime()
{
	return q_prime;
}

mpz_class& silvia_priv_key::get_n_prime()
{
	return n_prime;
}

////////////////////////////////////////////////////////////////////////////////
// Attribute class implementation
////////////////////////////////////////////////////////////////////////////////

silvia_attribute::silvia_attribute()
{
	attr_rep = 0;
}

////////////////////////////////////////////////////////////////////////////////
// String value attribute implementation
////////////////////////////////////////////////////////////////////////////////

silvia_string_attribute::silvia_string_attribute()
{
}

silvia_string_attribute::silvia_string_attribute(const std::string value)
{
	this->value = value;

	silvia_hash h(SYSPAR(hash_type));

	h.init();
	h.update((const unsigned char*) value.c_str(), value.size());

	this->attr_rep = h.final();
}

silvia_string_attribute& silvia_string_attribute::operator=(const std::string value)
{
	this->value = value;

	silvia_hash h(SYSPAR(hash_type));

	h.init();
	h.update((const unsigned char*) value.c_str(), value.size());

	this->attr_rep = h.final();
}

bool silvia_string_attribute::is_of_type(silvia_attr_t type)
{
	return type == SILVIA_STRING_ATTR;
}

std::string silvia_string_attribute::get_value()
{
	return value;
}

////////////////////////////////////////////////////////////////////////////////
// Integer value attribute implementation
////////////////////////////////////////////////////////////////////////////////

silvia_integer_attribute::silvia_integer_attribute()
{
}

silvia_integer_attribute::silvia_integer_attribute(const int value)
{
	this->attr_rep = value;
}


silvia_integer_attribute::silvia_integer_attribute(const mpz_class value)
{
	this->attr_rep = value;
}

silvia_integer_attribute& silvia_integer_attribute::operator=(const int value)
{
	this->attr_rep = value;

	return *this;
}

silvia_integer_attribute& silvia_integer_attribute::operator=(const mpz_class value)
{
	this->attr_rep = value;

	return *this;
}

bool silvia_integer_attribute::is_of_type(silvia_attr_t type)
{
	return type == SILVIA_INT_ATTR;
}

int silvia_integer_attribute::get_value()
{
	return (int) mpz_get_ui(attr_rep.get_mpz_t());
}

////////////////////////////////////////////////////////////////////////////////
// Boolean value attribute
////////////////////////////////////////////////////////////////////////////////

silvia_boolean_attribute::silvia_boolean_attribute()
{
}

silvia_boolean_attribute::silvia_boolean_attribute(const bool value)
{
	this->attr_rep = value ? 1 : 0;
}

silvia_boolean_attribute& silvia_boolean_attribute::operator=(const bool value)
{
	this->attr_rep = value ? 1 : 0;

	return *this;
}
	
bool silvia_boolean_attribute::is_of_type(silvia_attr_t type)
{
	return type == SILVIA_BOOL_ATTR;
}

bool silvia_boolean_attribute::get_value()
{
	return (mpz_get_ui(_Z(attr_rep)) == 1);
}

////////////////////////////////////////////////////////////////////////////////
// Credential
////////////////////////////////////////////////////////////////////////////////

silvia_credential::silvia_credential
(
	silvia_integer_attribute s,
	std::vector<silvia_attribute*> a,
	mpz_class A,
	mpz_class e,
	mpz_class v
) : s(s), attributes(a), A(A), e(e), v(v)
{
}

silvia_integer_attribute& silvia_credential::get_secret()
{
	return s;
}

size_t silvia_credential::num_attributes()
{
	return attributes.size();
}

silvia_attribute* silvia_credential::get_attribute(size_t i)
{
	return attributes[i];
}

mpz_class& silvia_credential::get_A()
{
	return A;
}

mpz_class& silvia_credential::get_e()
{
	return e;
}

mpz_class& silvia_credential::get_v()
{
	return v;
}

