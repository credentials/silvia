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
 silvia_irma_xmlreader.h

 XML reader that will read and parse the XML file types that are relevant for
 Silvia and the IRMA project
 *****************************************************************************/

#include "config.h"
#include <gmpxx.h>
#include "silvia_types.h"
#include "silvia_irma_xmlreader.h"
#include "silvia_macros.h"
#include <vector>
#include <memory>
#include <assert.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

// Initialise the one-and-only instance
/*static*/ std::auto_ptr<silvia_irma_xmlreader> silvia_irma_xmlreader::_i(NULL);

/*static*/ silvia_irma_xmlreader* silvia_irma_xmlreader::i()
{
	if (_i.get() == NULL)
	{
		_i = std::auto_ptr<silvia_irma_xmlreader>(new silvia_irma_xmlreader());
	}

	return _i.get();
}

silvia_verifier_specification* silvia_irma_xmlreader::read_verifier_spec(const std::string id_file_name, const std::string vd_file_name)
{
	////////////////////////////////////////////////////////////////////
	// Read the issuer description XML file
	////////////////////////////////////////////////////////////////////
	xmlDocPtr xmldoc = xmlParseFile(id_file_name.c_str());
	
	if (xmldoc == NULL)
	{
		return NULL;
	}
	
	// Check integrity
	xmlNodePtr root_elem = xmlDocGetRootElement(xmldoc);
	
	if ((root_elem == NULL) || (xmlStrcasecmp(root_elem->name, (const xmlChar*) "IssueSpecification") != 0))
	{
		xmlFreeDoc(xmldoc);
		
		return NULL;
	}
	
	// Parse the data
	unsigned short credential_id = 0;
	
	xmlNodePtr child_elem = root_elem->xmlChildrenNode;
	
	// Find the "Id" tag; this is the only tag we need from the issuer specification
	while ((child_elem != NULL) && (xmlStrcasecmp(child_elem->name, (const xmlChar*) "Id") != 0))
	{
		child_elem = child_elem->next;
	}
	
	if (child_elem == NULL)
	{
		xmlFreeDoc(xmldoc);
		
		return NULL;
	}
	
	xmlChar* id_value = xmlNodeListGetString(xmldoc, child_elem->xmlChildrenNode, 1);
	
	if (id_value == NULL)
	{
		xmlFreeDoc(xmldoc);
		
		return NULL;
	}
	
	credential_id = atoi((const char*) id_value);
	
	xmlFree(id_value);
	
	xmlFreeDoc(xmldoc);
	
	////////////////////////////////////////////////////////////////////
	// Read the verifier description XML file
	////////////////////////////////////////////////////////////////////
	
	xmldoc = xmlParseFile(vd_file_name.c_str());
	
	if (xmldoc == NULL)
	{
		return NULL;
	}
	
	// Check integrity
	root_elem = xmlDocGetRootElement(xmldoc);
	
	if ((root_elem == NULL) || (xmlStrcasecmp(root_elem->name, (const xmlChar*) "VerifySpecification") != 0))
	{
		xmlFreeDoc(xmldoc);
		
		return NULL;
	}
	
	// Parse the data
	std::string verifier_name;
	std::string short_msg;
	unsigned int verifier_id;
	std::vector<std::string> attribute_names;
	std::vector<bool> D;
	
	bool verifier_name_set = false;
	bool short_msg_set = false;
	bool verifier_id_set = false;
	bool attribute_names_set = false;
	bool D_set = false;
	
	// Add the expiry attribute since that will always be present
	// in an IRMA credential
	D.push_back(true);
	attribute_names.push_back("expires");
	
	child_elem = root_elem->xmlChildrenNode;
	
	while (child_elem != NULL)
	{
		if (xmlStrcasecmp(child_elem->name, (const xmlChar*) "Name") == 0)
		{
			xmlChar* name_value = xmlNodeListGetString(xmldoc, child_elem->xmlChildrenNode, 1);
			
			if (name_value != NULL)
			{
				short_msg = std::string((const char*) name_value);
				
				xmlFree(name_value);
				
				short_msg_set = true;
			}
		}
		else if (xmlStrcasecmp(child_elem->name, (const xmlChar*) "VerifierID") == 0)
		{
			xmlChar* verifier_id_value = xmlNodeListGetString(xmldoc, child_elem->xmlChildrenNode, 1);
			
			if (verifier_id_value != NULL)
			{
				verifier_name = std::string((const char*) verifier_id_value);
				
				xmlFree(verifier_id_value);
				
				verifier_name_set = true;
			}
		}
		else if (xmlStrcasecmp(child_elem->name, (const xmlChar*) "Id") == 0)
		{
			xmlChar* id_value = xmlNodeListGetString(xmldoc, child_elem->xmlChildrenNode, 1);
			
			if (id_value != NULL)
			{
				verifier_id = atoi((const char*) id_value);
				
				xmlFree(id_value);
				
				verifier_id_set = true;
			}
		}
		else if (xmlStrcasecmp(child_elem->name, (const xmlChar*) "AttributeModes") == 0)
		{
			xmlNodePtr attribute_mode = child_elem->xmlChildrenNode;
			
			while (attribute_mode != NULL)
			{
				if (xmlStrcasecmp(attribute_mode->name, (const xmlChar*) "AttributeMode") == 0)
				{
					xmlChar* attr_id_value = xmlGetProp(attribute_mode, (const xmlChar*) "id");
					
					if (attr_id_value == NULL)
					{
						xmlFreeDoc(xmldoc);
						
						return NULL;
					}
					
					attribute_names.push_back(std::string((const char*) attr_id_value));
					
					xmlFree(attr_id_value);
					
					xmlChar* mode_value = xmlGetProp(attribute_mode, (const xmlChar*) "mode");
					
					if (mode_value == NULL)
					{
						// Missing mandatory attribute
						xmlFreeDoc(xmldoc);
						
						return NULL;
					}
					
					if (xmlStrcasecmp(mode_value, (const xmlChar*) "revealed") == 0)
					{
						D.push_back(true);
					}
					else if (xmlStrcasecmp(mode_value, (const xmlChar*) "unrevealed") == 0)
					{
						D.push_back(false);
					}
					else
					{
						// Unknown value for mode
						xmlFreeDoc(xmldoc);
						
						return NULL;
					}
				}
				
				attribute_mode = attribute_mode->next;
			}
			
			attribute_names_set = true;
			D_set = true;
		}
		
		child_elem = child_elem->next;
	}
	
	xmlFreeDoc(xmldoc);
	
	if (!verifier_name_set || !short_msg_set || !verifier_id_set || !attribute_names_set || !D_set)
	{
		return NULL;
	}
	
	return new silvia_verifier_specification(verifier_name, short_msg, verifier_id, credential_id, attribute_names, D);
}
