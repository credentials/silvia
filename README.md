
##The Simple Library for Verifying and Issuing Attributes (Silvia)

Copyright (c) 2013-2014	Roland van Rijswijk-Deij  
Copyright (c) 2014	Antonio de la Piedra

All rights reserved. This software is distributed under a BSD-style
license. For more information, see LICENSE

###1. Introduction

Silvia is a C++ implementation of the IRMA card communication
protocol.  The software can be used to issue credentials to an IRMA
card and can verify already issued credentials. Moreover, using this library,
the cardholder can delete their credentials from the card, read the log, print the
contents of a given credential stored in the IRMA card and update their PINs.

###2. Prerequisites

To build the library:

 - GMP (>= 5.0), [ the GNU Multiple Precision Arithmetic Library ](https://gmplib.org/)
 - OpenSSL (>= 0.9.8), [ the Open Source toolkit for SSL/TLS ](http://www.openssl.org/)
 - libnfc (>= 1.7.0-rc8), [ the Public platform independent Near Field Communication (NFC) library ](http://nfc-tools.org/index.php?title=Libnfc)
 - libxml2 (>= 2.0), [ the XML C parser and toolkit ](http://xmlsoft.org/)

To run the tests:

 - CppUnit (>= 1.10), [ the C++ port of JUnit ](http://sourceforge.net/apps/mediawiki/cppunit/index.php?title=Main_Page)

###3. Building

To build the library, first clone the silvia repository:
```
$ git clone https://github.com/credentials/silvia
```
Then, in order to build the library, execute the following commands:
```
$ cd silvia
$ ./autogen.sh
$ ./configure
$ make
```
To build and run the tests (to check if the library functions correctly), execute the following command:
```
$ make check
```
###4. Installing 

To install the library as a regular user, run:
```
$ sudo make install
```
If you are root (administrative user), run:
```
# make install
```
###5. Using the library

Together with the library, silvia provides different clients for issuing and verifying credentials,
generating a Camenisch-Lysyanskaya (CL) keypair for a certain issuer and managing the IRMA card.

For basic usage, you need 3 xml specifications and 2 key files:
* An Issue Specification, which specifies the credentials to issue. Needed by the issuer.
* An Issuer Specification, which specifies who issued the credentials. Needed by the verifier.
* A verification specification, which specifies what credentials are verified. Needed by the verifier.
* A public key file of the issuer. Needed by both the issuer and the verifier.
* A private key file of the issuer. Needed by the issuer.

####5.1 Generating a CL keypair 

For generating a keypair for issuing and verifying credentials, ```silvia_keygen``` is utililzed:
```
$ ./silvia_keygen -h
Silvia issuer key generation utility 0.2.2

Usage:
        silvia_keygen -a <#-attribs> [-n <bits>] [-p <file>] [-P <file>] [-u <URI>]
        silvia_keygen -h
        silvia_keygen -v

        -a <#-attribs> Generate a key-pair supporting credentials with at most
                       <#-attribs> attributes per credentials
        -n <bits>      Generate a key-pair with a <bits>-bit modulus (defaults
                       to 2048)
        -p <file>      Output the public key to <file> (defaults to stdout)
        -P <file>      Output the private key to <file> (defaults to stdout)
        -u <URI>       Base URI used to reference other Idemix files (defaults to http://www.irmacard.org/credentials/)

        -h             Print this help message

        -v             Print the version number
```

IRMA relies on 1,024 bit keys and utilizes 6 attributes. We can create a new CL keypair as:
```
$ ./silvia_keygen -a 6 -n 1024 -p ipk.xml -P isk.xml
Writing public key to ipk.xml
Writing private key to isk.xml
Generating 1024-bit issuer key pair for 6 attributes ... OK
```
where ```ipk.xml``` is the public key of the issuer and ```isk.xml``` contains its private key.

####5.2 Issuing credentials

To issue a credential, you can create your own credential description or rely on the definitions
from [credentials/irma_configuration](https://github.com/credentials/irma_configuration).

You need both the public and private key file of the issuer, and an
issue specification (an xml file with root element
CredentialIssueSpecification).

In order to issue a new credential with the generated keys in Step 5.1, we use ```silvia_issuer```:
```
$ ./silvia_issuer -h
Silvia command-line IRMA issuer 0.2.2

Usage:
        silvia_issuer -I <issue-spec> -k <issuer-pubkey> -s <issuer-privkey> [-d] [-P] [-N]
        silvia_issuer -i <issue-script> [-d]
        silvia_issuer -h
        silvia_issuer -v

        -I <issue-spec>     Read issue specification from <issue-spec>
        -k <issuer-pubkey>  Read issuer public key from <issuer-pubkey>
        -s <issuer-privkey> Read issuer private key from <issuer-privkey>
        -d                  Print debug output
        -P                  Use PC/SC for card communication (default)
        -N                  Use NFC for card communication

        -i <issue-script>   Issue multiple credentials according to the
                            specified issuing script <issue-script>
        -d                  Print debug output

        -h                  Print this help message

        -v                  Print the version number
```

In this example, we use the credential description located at the test directory of the issuer client
(issuer/test/ageLower-test.xml):

```
<CredentialIssueSpecification>
        <Name>Minimum age</Name>
        <IssuerID>MijnOverheid</IssuerID>

        <Id>10</Id>

        <Expires>180</Expires> <!-- specified in days relative to date of issuance -->

        <Attributes>
                <Attribute type="string">
                        <Name>over12</Name>
                        <Value>yes</Value>
                </Attribute>
                <Attribute type="string">
                        <Name>over16</Name>
                        <Value>yes</Value>
                </Attribute>
                <Attribute type="string">
                        <Name>over18</Name>
                        <Value>yes</Value>
                </Attribute>
                <Attribute type="string">
                        <Name>over21</Name>
                        <Value>yes</Value>
                </Attribute>
        </Attributes>
</CredentialIssueSpecification>
```
This is consistent with the credential defined in https://github.com/credentials/irma_configuration/tree/master/MijnOverheid.
Then, we need to execute the following commands:
```
$ cd silvia/src/bin/issuer/
$ ./silvia_issuer -I test/ageLower-test.xml -k ipk.xml -s isk.xml 
```

####5.3 Verifying credentials

In order to verify the just issued credential, you need to get the
necessary files from [credentials/irma_configuration](https://github.com/credentials/irma_configuration).

You need the public key of the issuer, a verification specification
(an xml file with root element VerifySpecification), and an issuer
specification (an xml file with root element IssueSpecification).
Note that the issuer specification is not the same as the issue
specification used when issuing credentials.

Once you have the right files you can verify the credential using ```silvia_verifier```:
```
$ ./silvia_verifier -h
Silvia command-line IRMA verifier 0.2.2

Usage:
        silvia_verifier -I <issuer-spec> -V <verifier-spec> -k <issuer-pubkey> [-p] [-P] [-N]
        silvia_verifier -h
        silvia_verifier -v

        -I <issuer-spec>   Read issuer specification from <issuer-spec>
        -V <verifier-spec> Read verifier specification from <verifier-spec>
        -k <issuer-pubkey> Read issuer public key from <issuer-pubkey>
        -p                 Force PIN verification
        -P                 Use PC/SC for card communication (default)
        -N                 Use NFC for card communication

        -h                 Print this help message

        -v                 Print the version number
```

First, we clone the ```irma_configuration``` repository:

```
$ git clone https://github.com/credentials/irma_configuration/
```

In ```irma_configuration/MijnOverheid/Verifies/``` are located the different policies that
describe which attributes are revealed from the issued credential. For instance, in order to
perform a verification that requires revealing all the attributes of the credential we do:

```
$ cd silvia/src/bin/verifier
$ ./silvia_verifier -I irma_configuration/MijnOverheid/Issues/ageLower/description.xml -V irma_configuration/MijnOverheid/Verifies/ageLowerAll/description.xml -k ipk.xml
```

where ```ipk.xml``` is the public key of the issuer that we generated in Step 5.1, ```irma_configuration/MijnOverheid/Issues/ageLower/description.xml``` contains
the attributes of the credential we issued in Step 5.2, and ```irma_configuration/MijnOverheid/Verifies/ageLowerAll/description.xml``` is the
policy that requires all the attributes from the credential revealed.

####5.4 Managing the IRMA card

Using ```silvia_manager```, the cardholder can check the last operations performed
by the card, reading the credentials stored in IRMA and their attributes, deleting credentials
and changing her PINs:

```
$ ./silvia_manager 
Silvia command-line IRMA manager 0.2.2

Usage:
        silvia_manager [-lracso] [<credential>] [-P] [-N]
        silvia_manager -l Read the log of the IRMA card
        silvia_manager -r <credential> Remove a credential stored in the card
        silvia_manager -a Update admin pin
        silvia_manager -c Update credential pin
        silvia_manager -s List the credentials stored in the IRMA card
        silvia_manager -o <credential> Read all the attributes of <credential>

        -P                  Use PC/SC for card communication (default)
        -N                  Use NFC for card communication

        -d                  Print debug output

        -h                  Print this help message

        -v                  Print the version number
```

For instance, we can verify that we performed the operations described in Sections 5.1-5.3 by
executing:
```
$ ./silvia_manager -l
Silvia command-line IRMA manager 0.2.2


********************************************************************************
Waiting for card (PCSC) ...OK

=================================================
            PIN VERIFICATION REQUIRED            
=================================================

Please enter your administration PIN: 

Communicating with the card... OK
Entry 1: VERIFICATION
Policy: 003E
Credential: 10
Timestamp: Wed May 21 11:15:11 2014

Entry 2: ISSUANCE
Credential: 10
Timestamp: Wed May 21 11:01:43 2014
```

The field ```Policy``` refers to the number of attributes that were revealed
during the verification operation. The attributes that are revealed are encoded
as '1'. Therefore, for 6 attributes, where all were revealed with the exception of the master
secret (first attribute) we obtain: ```0x3e = 111110b```.

Also, we can read the list of credentials:
```
$ ./silvia_manager -s
Silvia command-line IRMA manager 0.2.2


********************************************************************************
Waiting for card (PCSC) ...OK

=================================================
            PIN VERIFICATION REQUIRED            
=================================================

Please enter your administration PIN: 

Communicating with the card... OK
Slot #0: 10
```
And then print the contents of their attributes:

```
$ ./silvia_manager -o 10
Silvia command-line IRMA manager 0.2.2


********************************************************************************
Waiting for card (PCSC) ...OK

=================================================
            PIN VERIFICATION REQUIRED            
=================================================

Please enter your new administration PIN: 

Communicating with the card... OK
Expiration date: Fri Nov 21 01:00:00 2014

Attribute [1]: yes
Attribute [2]: yes
Attribute [3]: yes
Attribute [4]: yes
OK
********************************************************************************
```

###6. Contact

Questions/remarks/suggestions/praise on this tool can be sent to:

Roland van Rijswijk-Deij 	<roland.vanrijswijk@surfnet.nl>  
Antonio de la Piedra 		<A.delaPiedra@cs.ru.nl>
