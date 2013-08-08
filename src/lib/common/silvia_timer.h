/* $Id: silvia_timer.h 57 2013-07-04 18:07:24Z rijswijk $ */

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
 silvia_timer.h

 Timer for testcases
 *****************************************************************************/

#ifndef _SILVIA_TIMER_H
#define _SILVIA_TIMER_H

#include "config.h"
#include <memory>
#include <stdlib.h>
#include <time.h>

#ifdef __MACH__

#define CLOCK_MONOTONIC 1

#endif // __MACH__

#ifdef __MINGW32__

#define CLOCK_MONOTONIC 1

#ifndef _TIMESPEC_DEFINED
#define _TIMESPEC_DEFINED
/* POSIX.1b structure for a time value.  This is like a `struct timeval' but
   has nanoseconds instead of microseconds.  */
struct timespec {
  long int tv_sec;		/* Seconds.  */
  long int tv_nsec;	/* Nanoseconds.  */
};
#endif // _TIMESPEC_DEFINED

#endif // __MINGW32__

/**
 * Timer class
 */
class silvia_timer
{
public:
	// Mark the current time
	void mark();
	
	// Compute the elapsed time since marking
	unsigned long long elapsed();

private:
	// State
	struct timespec mark_time;
};

#endif // !_SILVIA_TIMER_H
