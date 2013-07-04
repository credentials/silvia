/* $Id: syspartests.cpp 50 2013-06-30 11:28:35Z rijswijk $ */

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
 syspartests.cpp

 Tests the common syspar implementations
 *****************************************************************************/

#include <stdlib.h>
#include <cppunit/extensions/HelperMacros.h>
#include "syspartests.h"
#include "silvia_parameters.h"

CPPUNIT_TEST_SUITE_REGISTRATION(syspar_tests);

void syspar_tests::setUp()
{
}

void syspar_tests::tearDown()
{
}

void syspar_tests::test_syspars()
{
	CPPUNIT_ASSERT(silvia_system_parameters::i()->get_l_n() == 2048);
	CPPUNIT_ASSERT(silvia_system_parameters::i()->get_l_m() == 256);
	CPPUNIT_ASSERT(silvia_system_parameters::i()->get_l_e() == 597);
	CPPUNIT_ASSERT(silvia_system_parameters::i()->get_l_e_prime() == 120);
	CPPUNIT_ASSERT(silvia_system_parameters::i()->get_l_v() == 2724);
	CPPUNIT_ASSERT(silvia_system_parameters::i()->get_l_statzk() == 80);
	CPPUNIT_ASSERT(silvia_system_parameters::i()->get_l_H() == 256);
	CPPUNIT_ASSERT(SYSPAR(l_n) == 2048);
	CPPUNIT_ASSERT(SYSPAR(l_m) == 256);
	CPPUNIT_ASSERT(SYSPAR(l_e) == 597);
	CPPUNIT_ASSERT(SYSPAR(l_e_prime) == 120);
	CPPUNIT_ASSERT(SYSPAR(l_v) == 2724);
	CPPUNIT_ASSERT(SYSPAR(l_statzk) == 80);
	CPPUNIT_ASSERT(SYSPAR(l_H) == 256);

	silvia_system_parameters::i()->set_l_n(1024);
	CPPUNIT_ASSERT(silvia_system_parameters::i()->get_l_n() == 1024);

	silvia_system_parameters::i()->set_l_m(128);
	CPPUNIT_ASSERT(silvia_system_parameters::i()->get_l_m() == 128);

	silvia_system_parameters::i()->set_l_e(127);
	CPPUNIT_ASSERT(silvia_system_parameters::i()->get_l_e() == 127);

	silvia_system_parameters::i()->set_l_e_prime(84);
	CPPUNIT_ASSERT(silvia_system_parameters::i()->get_l_e_prime() == 84);

	silvia_system_parameters::i()->set_l_v(1234);
	CPPUNIT_ASSERT(silvia_system_parameters::i()->get_l_v() == 1234);

	silvia_system_parameters::i()->set_l_statzk(40);
	CPPUNIT_ASSERT(silvia_system_parameters::i()->get_l_statzk() == 40);

	silvia_system_parameters::i()->set_l_H(160);
	CPPUNIT_ASSERT(silvia_system_parameters::i()->get_l_H() == 160);
}

