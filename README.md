$Id: README 42 2013-06-20 12:47:04Z rijswijk $

Copyright (c) 2013 Roland van Rijswijk-Deij

All rights reserved. This software is distributed under a BSD-style
license. For more information, see LICENSE

1. INTRODUCTION
===============


2. PREREQUISITES
================

To build the library:

 - GMP (>= 5.0), the GNU Multiple Precision Arithmetic Library
 - OpenSSL (>= 0.9.8), the Open Source toolkit for SSL/TLS

To run the tests:

 - CppUnit (>= 1.10), the C++ port of JUnit

3. BUILDING
===========

To build the library, execute the following commands:

    ./autogen.sh
    ./configure
    make

To build and run the tests (to check if the library functions correctly), execute  the following command:

    make check

4. INSTALLING
=============

To install the library as a regular user, run:

    sudo make install

If you are root (administrative user), run:

    make install

5. USING THE LIBRARY
====================


6. CONTACT
==========

Questions/remarks/suggestions/praise on this tool can be sent to:

Roland van Rijswijk-Deij <rijswijk@cs.ru.nl, roland@mazuki.nl>
