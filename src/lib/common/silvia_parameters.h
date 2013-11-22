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

#ifndef _SILVIA_PARAMETERS_H
#define _SILVIA_PARAMETERS_H

#include <memory>
#include <string>
#include <stdlib.h>

#define SYSPAR(par) silvia_system_parameters::i()->get_##par()

#define SYSPAR_BYTES(par) ((silvia_system_parameters::i()->get_##par() / 8) + ((silvia_system_parameters::i()->get_##par() % 8) != 0 ? 1 : 0))

/**
 * System parameters (singleton)
 */
class silvia_system_parameters
{
public:
	/**
	 * Get the one-and-only instance
	 * @return the one-and-only instance
	 */
	static silvia_system_parameters* i();

	/**
	 * Set l_n
	 * @param l_n new value for l_n
	 */
	void set_l_n(size_t l_n);

	/**
	 * Get l_n
	 * @return the value for l_n
	 */
	size_t get_l_n();

	/**
	 * Set l_m
	 * @param l_m new value for l_m
	 */
	void set_l_m(size_t l_m);

	/**
	 * Get l_m
	 * @return the value for l_m
	 */
	size_t get_l_m();

	/**
	 * Set l_e
	 * @param l_e new value for l_e
	 */
	void set_l_e(size_t l_e);

	/**
	 * Get l_e
	 * @return the value for l_e
	 */
	size_t get_l_e();

	/**
	 * Set l_prime_e
	 * @param l_prime_e new value for l_e'
	 */
	void set_l_e_prime(size_t l_e_prime);

	/**
	 * Get l_prime_e
	 * @return the value for l_e'
	 */
	size_t get_l_e_prime();

	/**
	 * Set l_v
	 * @param l_v new value for l_v
	 */
	void set_l_v(size_t l_v);

	/**
	 * Get l_v
	 * @return the value for l_v
	 */
	size_t get_l_v();

	/**
	 * Set l_statzk
	 * @param l_statzk new value for l_statzk
	 */
	void set_l_statzk(size_t l_statzk);

	/**
	 * Get l_statzk
	 * @return the value for l_statzk
	 */
	size_t get_l_statzk();

	/**
	 * Set l_H
	 * @param l_H new value for l_H
	 */
	void set_l_H(size_t l_H);

	/**
	 * Get l_H
	 * @return the value for l_H
	 */
	size_t get_l_H();
	
	/**
	 * Set the hash type
	 * @param hash_type new value for the hash type
	 */
	void set_hash_type(std::string hash_type);
	
	/**
	 * Get the hash type
	 * @return the hash type to use
	 */
	std::string get_hash_type();
	
	/**
	 * Set the primality test error boundary; influences the number of
	 * invocations of the Rabin-Miller primality test while selecting
	 * p, q and e.
	 * @param l_pt primality test error boundary
	 */
	void set_l_pt(size_t l_pt);
	
	/**
	 * Set the primality test error boundary; influences the number of
	 * invocations of the Rabin-Miller primality test while selecting
	 * p, q and e.
	 * @return the primality test error boundary
	 */
	size_t get_l_pt();
	
	/**
	 * Returns the number of invocations of the Rabin-Miller primality
	 * test for the currently set error boundary
	 * @return the number of iterations the Rabin-Miller primality
	 * test should be invoked to satisfy the error bound set for
	 * prime generation.
	 */
	size_t get_rabin_miller_its();
	
	/**
	 * Reset system parameters to default values
	 */
	void reset();

private:
	// Constructor
	silvia_system_parameters();

	// The one-and-only instance
	static std::auto_ptr<silvia_system_parameters> _i;

	// The system parameters
	size_t l_n;
	size_t l_m;
	size_t l_e;
	size_t l_e_prime;
	size_t l_v;
	size_t l_statzk;
	size_t l_H;
	size_t l_pt;
	size_t rabin_miller_its;
	std::string hash_type;
};

#endif // !_SILVIA_PARAMETERS_H

