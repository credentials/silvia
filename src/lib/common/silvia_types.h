/* $Id: silvia_types.h 52 2013-07-02 13:16:24Z rijswijk $ */

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
 silvia_types.h

 Generic type definitions
 *****************************************************************************/

#ifndef _SILVIA_TYPES_H
#define _SILVIA_TYPES_H

#include <gmpxx.h>
#include <vector>
#include <string>

class bytestring;

/**
 * Issuer public key
 */
class silvia_pub_key
{
public:
	/**
	 * Constructor from specified values
	 * @param n the modulus
	 * @param S the S value
	 * @param Z the Z value
	 * @param R the attribute specific values
	 */
	silvia_pub_key(mpz_class n, mpz_class S, mpz_class Z, std::vector<mpz_class> R);

	/**
	 * Destructor
	 */
	~silvia_pub_key();

	/**
	 * Get the modulus
	 * @return a reference to the modulus
	 */
	mpz_class& get_n();

	/**
	 * Get the S value
	 * @return a reference to the S value
	 */
	mpz_class& get_S();

	/**
	 * Get the Z value
	 * @return a reference to the Z value
	 */
	mpz_class& get_Z();
	
	/**
	 * Get the R values
	 * @return a reference to a std::vector with the R values
	 */
	std::vector<mpz_class>& get_R();
	
private:
	// Public key values
	mpz_class		n;
	mpz_class 		S;
	mpz_class		Z;
	std::vector<mpz_class>	R;
};

/**
 * Issuer private key
 */
class silvia_priv_key
{
public:
	/**
	 * Constructor from specified values
	 * @param p the first prime (p)
	 * @param q the second prime (q)
	 */
	silvia_priv_key(mpz_class p, mpz_class q);

	/**
	 * Destructor
	 */
	~silvia_priv_key();

	/**
	 * Get the first prime (p)
	 * @return the first prime (p)
	 */
	mpz_class& get_p();

	/**
	 * Get the second prime (q)
	 * @return the second prime (q)
	 */
	mpz_class& get_q();

	/**
	 * Get the first prime's Sophie Germain progenitor
	 * @return the Sophie Germain base of p, p'
	 */
	mpz_class& get_p_prime();

	/**
	 * Get the second prime's Sophie Germain progenitor
	 * @return the Sophie Germain base of q, q'
	 */
	mpz_class& get_q_prime();
	
	/**
	 * Get modulus n' based on p' and q'
	 * @return modulus n'
	 */
	mpz_class& get_n_prime();

private:
	// Private key values
	mpz_class	p;
	mpz_class 	q;
	mpz_class	p_prime;
	mpz_class	q_prime;
	mpz_class	n_prime;
};

/**
 * Attribute types
 */
typedef enum
{
	SILVIA_UNDEFINED_ATTR,	/**< this is an attribute of an undefined type */
	SILVIA_STRING_ATTR,	/**< this is a string attribute */
	SILVIA_INT_ATTR,	/**< this is an integer attribute */
	SILVIA_BOOL_ATTR	/**< this is a boolean attribute */
}
silvia_attr_t;

/**
 * Generic attribute
 */
class silvia_attribute
{
public:
	/**
	 * Destructor
	 */
	virtual ~silvia_attribute() { }

	/**
	 * Get a computable representation
	 * @return a computable representation of the attribute
	 */
	virtual mpz_class& rep() { return attr_rep; }
	
	/**
	 * Get a string with a integer representation
	 * @return a string with an integer representation of the attribute
	 */
	std::string int_rep();
	
	/**
	 * Get a padded bytestring representation
	 * @return a 0-padded bytestring representation of l_m
	 */
	bytestring bs_rep();
	
	/**
	 * Recreate the attribute from the representation
	 * @param rep the representation
	 */
	virtual void from_rep(const mpz_class& rep) = 0;

	/**
	 * Equals
	 * @return true if both sides are equal
	 */
	virtual bool operator==(const silvia_attribute& rh) { return rh.attr_rep == this->attr_rep; }

	/**
	 * Is the attribute of the specified type?
	 * @return true if the attribute is of the specified type
	 */
	virtual bool is_of_type(silvia_attr_t type) { return SILVIA_UNDEFINED_ATTR; }

protected:
	/**
	 * Default constructor is private!
	 */
	silvia_attribute();

	// Computable representation of the attribute
	mpz_class	attr_rep;
};

/**
 * String value attribute
 */
class silvia_string_attribute : public silvia_attribute
{
public:
	/**
	 * Constructor
	 */
	silvia_string_attribute();

	/**
	 * Constructor
	 * @param value the attribute value
	 */
	silvia_string_attribute(const std::string value);

	/**
	 * Assignment
	 * @param rh what value to assign
	 */
	virtual silvia_string_attribute& operator=(const std::string value);

	/**
	 * Is the attribute of the specified type?
	 * @return true if the specified type is SILVIA_STRING_ATTR
	 */
	virtual bool is_of_type(silvia_attr_t type);

	/**
	 * Get the value
	 * @return the value of the attribute
	 */
	std::string get_value();
	
	/**
	 * Recreate the attribute from the representation
	 * @param rep the representation
	 */
	virtual void from_rep(const mpz_class& rep);

private:
	// String value
	std::string	value;
};

/**
 * Integer value attribute
 */
class silvia_integer_attribute : public silvia_attribute
{
public:
	/**
	 * Constructor
	 */
	silvia_integer_attribute();

	/**
	 * Constructor
	 * @param value the attribute value
	 */
	silvia_integer_attribute(const int value);

	/**
	 * Constructor
	 * @param value the attribute value
	 */
	silvia_integer_attribute(const mpz_class value);

	/**
	 * Assignment
	 * @param rh what value to assign
	 */
	virtual silvia_integer_attribute& operator=(const int value);

	/**
	 * Assignment
	 * @param rh what value to assign
	 */
	virtual silvia_integer_attribute& operator=(const mpz_class value);

	/**
	 * Is the attribute of the specified type?
	 * @return true if the specified type is SILVIA_INT_ATTR
	 */
	virtual bool is_of_type(silvia_attr_t type);

	/**
	 * Get the value
	 * @return the value of the attribute
	 */
	int get_value();
	
	/**
	 * Recreate the attribute from the representation
	 * @param rep the representation
	 */
	virtual void from_rep(const mpz_class& rep);
};

/**
 * Boolean value attribute
 */
class silvia_boolean_attribute : public silvia_attribute
{
public:
	/**
	 * Constructor
	 */
	silvia_boolean_attribute();

	/**
	 * Constructor
	 * @param value the attribute value
	 */
	silvia_boolean_attribute(const bool value);

	/**
	 * Assignment
	 * @param rh what value to assign
	 */
	virtual silvia_boolean_attribute& operator=(const bool value);

	/**
	 * Is the attribute of the specified type?
	 * @return true if the specified type is SILVIA_BOOL_ATTR
	 */
	virtual bool is_of_type(silvia_attr_t type);

	/**
	 * Get the value
	 * @return the value of the attribute
	 */
	bool get_value();
	
	/**
	 * Recreate the attribute from the representation
	 * @param rep the representation
	 */
	virtual void from_rep(const mpz_class& rep);
};

/**
 * Credential
 */
class silvia_credential
{
public:
	/**
	 * Constructor
	 * @param s the credential secret
	 * @param a the attributes for this credential
	 * @param A the A value of the CL signature for this credential
	 * @param e prime e of the CL signature for this credential
	 * @param v the v value of the CL signature for this credential
	 */
	silvia_credential
	(
		silvia_integer_attribute s,
		std::vector<silvia_attribute*> a,
		mpz_class A,
		mpz_class e,
		mpz_class v
	);

	/**
	 * Destructor
	 */
	virtual ~silvia_credential() { }

	/**
	 * Get the secret for this credential
	 * @return the secret for this credential
	 */
	silvia_integer_attribute& get_secret();

	/**
	 * Get the number of attributes for this credential
	 * @return the number of attributes for this credential
	 */
	size_t num_attributes();

	/**
	 * Get the i-th attribute for this credential
	 * @param i which attribute to fetch
	 * @return the i-th attribute for this credential
	 */
	silvia_attribute* get_attribute(size_t i);

	/**
	 * Get the A value of the CL signature for this credential
	 * @return the A value of the CL signature for this credential
	 */
	mpz_class& get_A();

	/**
	 * Get prime e of the CL signature for this credential
	 * @return prime e of the CL signature for this credential
	 */
	mpz_class& get_e();

	/**
	 * Get the v value of the CL signature for this credential
	 * @return the v value of the CL signature for this credential
	 */
	mpz_class& get_v();
	
	/**
	 * Get all attributes
	 * @return a vector with all attributes
	 */
	const std::vector<silvia_attribute*>& get_attributes();

private:
	// The credential secret
	silvia_integer_attribute s;

	// The attributes of the credential
	std::vector<silvia_attribute*> attributes;

	// The Camenisch-Lysyanskaya signature on the credential
	mpz_class A;
	mpz_class e;
	mpz_class v;
};

#endif // !_SILVIA_TYPES_H

