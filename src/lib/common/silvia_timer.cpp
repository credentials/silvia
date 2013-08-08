/* $Id: silvia_timer.cpp 57 2013-07-04 18:07:24Z rijswijk $ */

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
 silvia_timer.cpp

 Timer for testcases
 *****************************************************************************/

#include "config.h"
#include "silvia_timer.h"
#include <time.h>

#ifdef __MACH__

/*
 * Mac OS X does not have clock_gettime for some reason
 *
 * Use solution from here to fix it:
 * http://stackoverflow.com/questions/5167269/clock-gettime-alternative-in-mac-os-x
 */

#include <mach/clock.h>
#include <mach/mach.h>

void clock_gettime(int clock, struct timespec* the_time)
{
	clock_serv_t cclock;
	mach_timespec_t mts;

	host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);
	clock_get_time(cclock, &mts);
	mach_port_deallocate(mach_task_self(), cclock);
	
	the_time->tv_sec = mts.tv_sec;
	the_time->tv_nsec = mts.tv_nsec;
}

#endif // __MACH__

#ifdef __MINGW32__

/*
 * MinGW does not have clock_gettime for some reason
 *
 * Use solution from here to fix it:
 * http://stackoverflow.com/questions/5404277/porting-clock-gettime-to-windows
 */

#include <stdarg.h>
#include <windef.h>
#include <winnt.h>
#include <winbase.h>

LARGE_INTEGER getFILETIMEoffset()
{
    SYSTEMTIME s;
    FILETIME f;
    LARGE_INTEGER t;

    s.wYear = 1970;
    s.wMonth = 1;
    s.wDay = 1;
    s.wHour = 0;
    s.wMinute = 0;
    s.wSecond = 0;
    s.wMilliseconds = 0;
    SystemTimeToFileTime(&s, &f);
    t.QuadPart = f.dwHighDateTime;
    t.QuadPart <<= 32;
    t.QuadPart |= f.dwLowDateTime;
    return (t);
}

void clock_gettime(int X, struct timespec *ts)
{
    LARGE_INTEGER           t;
    FILETIME            f;
    double                  nanoseconds;
    static LARGE_INTEGER    offset;
    static double           frequencyToNanoseconds;
    static int              initialized = 0;
    static BOOL             usePerformanceCounter = 0;

    if (!initialized) {
        LARGE_INTEGER performanceFrequency;
        initialized = 1;
        usePerformanceCounter = QueryPerformanceFrequency(&performanceFrequency);
        if (usePerformanceCounter) {
            QueryPerformanceCounter(&offset);
            frequencyToNanoseconds = (double)performanceFrequency.QuadPart / 1000.;
        } else {
            offset = getFILETIMEoffset();
            frequencyToNanoseconds = 0.010;
        }
    }
    if (usePerformanceCounter) QueryPerformanceCounter(&t);
    else {
        GetSystemTimeAsFileTime(&f);
        t.QuadPart = f.dwHighDateTime;
        t.QuadPart <<= 32;
        t.QuadPart |= f.dwLowDateTime;
    }

    t.QuadPart -= offset.QuadPart;
    nanoseconds = (double)t.QuadPart / frequencyToNanoseconds;
    t.QuadPart = nanoseconds;
    ts->tv_sec = t.QuadPart / 1000000000;
    ts->tv_nsec = t.QuadPart % 1000000000;
}

#endif // __MINGW32__

void silvia_timer::mark()
{
	clock_gettime(CLOCK_MONOTONIC, &mark_time);
}
	
unsigned long long silvia_timer::elapsed()
{
	static struct timespec now;
	
	clock_gettime(CLOCK_MONOTONIC, &now);
	
	unsigned long long elapsed = 0;
	
	elapsed = now.tv_sec - mark_time.tv_sec;
	elapsed *= 1000*1000*1000;
	
	if (mark_time.tv_nsec > now.tv_nsec)
	{
		elapsed -= (mark_time.tv_nsec - now.tv_nsec);
	}
	else
	{
		elapsed += (now.tv_nsec - mark_time.tv_nsec);
	}
	
	return elapsed;
}
