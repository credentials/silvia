Copyright (c) 2013 Roland van Rijswijk-Deij

All rights reserved. This software is distributed under a BSD-style
license. For more information, see LICENSE

1. INTRODUCTION
===============

Silvia is a C++ implementation of the IRMA card communication
protocol.  The software can be used to issue credentials to an IRMA
card and can verify already issued credentials.

2. PREREQUISITES
================

To build the library:

 - GMP (>= 5.0), [ the GNU Multiple Precision Arithmetic Library ](https://gmplib.org/)
 - OpenSSL (>= 0.9.8), [ the Open Source toolkit for SSL/TLS ](http://www.openssl.org/)
 - libnfc (>= 1.7.0-rc8), [ the Public platform independent Near Field Communication (NFC) library ](http://nfc-tools.org/index.php?title=Libnfc)
 - libxml2 (>= 2.0), [ the XML C parser and toolkit ](http://xmlsoft.org/)

To run the tests:

 - CppUnit (>= 1.10), [ the C++ port of JUnit ](http://sourceforge.net/apps/mediawiki/cppunit/index.php?title=Main_Page)

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

To issue a credential, execute the following command:

    silvia_issue -I src/bin/issuer/test/ageLower-test.xml -k src/bin/issuer/test/ipk.xml -s src/bin/issuer/test/isk.xml

In order to verify the just issued credential, you need to get the
necessary files from [credentials/irma_configuration](https://github.com/credentials/irma_configuration).
Once you have the right files you can verify the credential with the
following command:

    silvia_verifier -I irma_configuration/MijnOverheid/Issues/ageLower/description.xml -V irma_configuration/MijnOverheid/Verifies/ageLowerAll/description.xml -k irma_configuration/MijnOverheid/ipk.xml

6. CONTACT
==========

Questions/remarks/suggestions/praise on this tool can be sent to:

Roland van Rijswijk-Deij <rijswijk@cs.ru.nl>, <roland@mazuki.nl>
