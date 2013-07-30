/* $Id$ */

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
 silvia_idemix_xmlreader.h

 XML reader that will read and parse the XML file types that are relevant for
 Silvia and the IRMA project
 *****************************************************************************/

#include "config.h"
#include <gmpxx.h>
#include "silvia_types.h"
#include "silvia_idemix_xmlreader.h"
#include "silvia_macros.h"
#include <vector>
#include <memory>
#include <assert.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

// Initialise the one-and-only instance
/*static*/ std::auto_ptr<silvia_idemix_xmlreader> silvia_idemix_xmlreader::_i(NULL);

/*static*/ silvia_idemix_xmlreader* silvia_idemix_xmlreader::i()
{
	if (_i.get() == NULL)
	{
		_i = std::auto_ptr<silvia_idemix_xmlreader>(new silvia_idemix_xmlreader());
	}

	return _i.get();
}

silvia_pub_key* silvia_idemix_xmlreader::read_idemix_pubkey(const std::string file_name)
{
	// Read the XML file
	xmlDocPtr xmldoc = xmlParseFile(file_name.c_str());
	
	if (xmldoc == NULL)
	{
		return NULL;
	}
	
	// Check integrity
	xmlNodePtr root_elem = xmlDocGetRootElement(xmldoc);
	
	if ((root_elem == NULL) || (xmlStrcasecmp(root_elem->name, (const xmlChar*) "IssuerPublicKey") != 0))
	{
		xmlFreeDoc(xmldoc);
		
		return NULL;
	}
	
	// Parse the data
	mpz_class S;
	mpz_class Z;
	mpz_class n;
	size_t base_count = 0;
	std::vector<mpz_class> R;
	
	bool S_set = false;
	bool Z_set = false;
	bool n_set = false;
	bool R_set = false;
	
	xmlNodePtr child_elem = root_elem->xmlChildrenNode;
	
	// Find the "Elements" tag
	while ((child_elem != NULL) && (xmlStrcasecmp(child_elem->name, (const xmlChar*) "Elements") != 0))
	{
		child_elem = child_elem->next;
	}
	
	if (child_elem == NULL)
	{
		xmlFreeDoc(xmldoc);
		
		return NULL;
	}
	
	// Now parse the elements
	xmlNodePtr elements = child_elem->xmlChildrenNode;
	
	while(elements != NULL)
	{
		if (xmlStrcasecmp(elements->name, (const xmlChar*) "S") == 0)
		{
			// Retrieve the value for S; this is a string
			xmlChar* S_value = xmlNodeListGetString(xmldoc, elements->xmlChildrenNode, 1);
			
			if (S_value != NULL)
			{
				S = mpz_class((const char*) S_value);
				
				xmlFree(S_value);
				
				S_set = true;
			}
		}
		else if (xmlStrcasecmp(elements->name, (const xmlChar*) "Z") == 0)
		{
			// Retrieve the value for Z; this is a string
			xmlChar* Z_value = xmlNodeListGetString(xmldoc, elements->xmlChildrenNode, 1);
			
			if (Z_value != NULL)
			{
				Z = mpz_class((const char*) Z_value);
				
				xmlFree(Z_value);
				
				Z_set = true;
			}
		}
		else if (xmlStrcasecmp(elements->name, (const xmlChar*) "n") == 0)
		{
			// Retrieve the value for n; this is a string
			xmlChar* n_value = xmlNodeListGetString(xmldoc, elements->xmlChildrenNode, 1);
			
			if (n_value != NULL)
			{
				n = mpz_class((const char*) n_value);
				
				xmlFree(n_value);
				
				n_set = true;
			}
		}
		else if (xmlStrcasecmp(elements->name, (const xmlChar*) "Bases") == 0)
		{
			// Retrieve the number of bases
			xmlChar* base_count_str = xmlGetProp(elements, (const xmlChar*) "num");
			
			if (base_count_str == NULL)
			{
				xmlFreeDoc(xmldoc);
				
				return NULL;
			}
			
			base_count = atoi((const char*) base_count_str);
			
			xmlNodePtr bases = elements->xmlChildrenNode;
			
			for (size_t i = 0; i < base_count; i++)
			{
				char base_name[256];
				
				sprintf(base_name, "Base_%zd", i);
				
				xmlNodePtr base = bases;
				
				while (base != NULL)
				{
					if (xmlStrcasecmp(base->name, (const xmlChar*) base_name) == 0)
					{
						xmlChar* R_value = xmlNodeListGetString(xmldoc, base->xmlChildrenNode, 1);
						
						if (R_value != NULL)
						{
							mpz_class R_i = mpz_class((const char*) R_value);
							
							xmlFree(R_value);
							
							R.push_back(R_i);
						}
						
						break;
					}
					
					base = base->next;
				}
			}
			
			R_set = R.size() == base_count;
		}
		
		elements = elements->next;
	}
	
	xmlFreeDoc(xmldoc);
	
	if (!S_set || !Z_set || !n_set || !R_set)
	{
		return NULL;
	}
	
	return new silvia_pub_key(n, S, Z, R);
}

silvia_priv_key* silvia_idemix_xmlreader::read_idemix_privkey(const std::string file_name)
{
	// Read the XML file
	xmlDocPtr xmldoc = xmlParseFile(file_name.c_str());
	
	if (xmldoc == NULL)
	{
		return NULL;
	}
	
	// Check integrity
	xmlNodePtr root_elem = xmlDocGetRootElement(xmldoc);
	
	if ((root_elem == NULL) || (xmlStrcasecmp(root_elem->name, (const xmlChar*) "IssuerPrivateKey") != 0))
	{
		xmlFreeDoc(xmldoc);
		
		return NULL;
	}
	
	// Parse the data
	mpz_class p;
	mpz_class q;
	
	bool p_set = false;
	bool q_set = false;
	
	xmlNodePtr child_elem = root_elem->xmlChildrenNode;
	
	// Find the "Elements" tag
	while ((child_elem != NULL) && (xmlStrcasecmp(child_elem->name, (const xmlChar*) "Elements") != 0))
	{
		child_elem = child_elem->next;
	}
	
	if (child_elem == NULL)
	{
		xmlFreeDoc(xmldoc);
		
		return NULL;
	}
	
	// Now parse the elements
	xmlNodePtr elements = child_elem->xmlChildrenNode;
	
	while(elements != NULL)
	{
		if (xmlStrcasecmp(elements->name, (const xmlChar*) "p") == 0)
		{
			// Retrieve the value for p; this is a string
			xmlChar* p_value = xmlNodeListGetString(xmldoc, elements->xmlChildrenNode, 1);
			
			if (p_value != NULL)
			{
				p = mpz_class((const char*) p_value);
				
				xmlFree(p_value);
				
				p_set = true;
			}
		}
		else if (xmlStrcasecmp(elements->name, (const xmlChar*) "q") == 0)
		{
			// Retrieve the value for q; this is a string
			xmlChar* q_value = xmlNodeListGetString(xmldoc, elements->xmlChildrenNode, 1);
			
			if (q_value != NULL)
			{
				q = mpz_class((const char*) q_value);
				
				xmlFree(q_value);
				
				q_set = true;
			}
		}
		
		elements = elements->next;
	}
	
	xmlFreeDoc(xmldoc);
	
	if (!p_set || !q_set)
	{
		return NULL;
	}
	
	return new silvia_priv_key(p, q);
}
