/* $Id: issuetests.h 52 2013-07-02 13:16:24Z rijswijk $ */

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
 issuetests.cpp

 Test credential issuance
 *****************************************************************************/

#ifndef _SILVIA_ISSUER_ISSUETESTS_H
#define _SILVIA_ISSUER_ISSUETESTS_H

#include "config.h"
#include <cppunit/extensions/HelperMacros.h>
#include "silvia_issuer.h"
#include "silvia_types.h"

class issue_tests : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(issue_tests);
	CPPUNIT_TEST(test_issuance_irma_testvec);
	CPPUNIT_TEST(test_irma_issuer);
	CPPUNIT_TEST_SUITE_END();

public:
	void test_issuance_irma_testvec();
	void test_irma_issuer();

	void setUp();
	void tearDown();
};

#endif // !_SILVIA_ISSUER_ISSUETESTS_H

