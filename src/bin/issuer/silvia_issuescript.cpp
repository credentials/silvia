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
 silvia_issuescript.h

 XML reader that will read and parse a Silvia issuing script
 *****************************************************************************/

#include "config.h"
#include "silvia_types.h"
#include "silvia_issuescript.h"
#include "silvia_macros.h"
#include "silvia_bytestring.h"
#include <vector>
#include <memory>
#include <assert.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <time.h>

silvia_issuescript::silvia_issuescript(const std::string file_name)
{
	is_valid = false;

	////////////////////////////////////////////////////////////////////
	// Read the issuing script
	////////////////////////////////////////////////////////////////////
	xmlDocPtr xmldoc = xmlParseFile(file_name.c_str());
	
	if (xmldoc == NULL)
	{
		return;
	}
	
	// Check integrity
	xmlNodePtr root_elem = xmlDocGetRootElement(xmldoc);
	
	if ((root_elem == NULL) || (xmlStrcasecmp(root_elem->name, (const xmlChar*) "SilviaIssuingScript") != 0))
	{
		xmlFreeDoc(xmldoc);
	
		return;
	}
	
	// Parse the data
	xmlNodePtr child_elem = root_elem->xmlChildrenNode;

	bool userPIN_set = false;
	bool atLeastOneCredSpec = false;
	
	while (child_elem != NULL)
	{
		if (xmlStrcasecmp(child_elem->name, (const xmlChar*) "Description") == 0)
		{
			xmlChar* description_value = xmlNodeListGetString(xmldoc, child_elem->xmlChildrenNode, 1);
			
			if (description_value != NULL)
			{
				description = std::string((const char*) description_value);
				
				xmlFree(description_value);
			}
		}
		else if (xmlStrcasecmp(child_elem->name, (const xmlChar*) "UserPIN") == 0)
		{
			xmlChar* userPIN_value = xmlNodeListGetString(xmldoc, child_elem->xmlChildrenNode, 1);

			if (userPIN_value != NULL)
			{
				userPIN = std::string((const char*) userPIN_value);

				xmlFree(userPIN_value);

				userPIN_set = true;
			}
		}
		else if (xmlStrcasecmp(child_elem->name, (const xmlChar*) "Credentials") == 0)
		{
			xmlNodePtr credentials = child_elem->xmlChildrenNode;
			
			while (credentials != NULL)
			{
				if (xmlStrcasecmp(credentials->name, (const xmlChar*) "Credential") == 0)
				{
					std::string issueSpec;
					std::string issuerIPK;
					std::string issuerISK;

					xmlNodePtr credential_info = credentials->xmlChildrenNode;

					while (credential_info != NULL)
					{
						if (xmlStrcasecmp(credential_info->name, (const xmlChar*) "IssueSpecification") == 0)
						{
							xmlChar* issueSpec_value = xmlNodeListGetString(xmldoc, credential_info->xmlChildrenNode, 1);

							if (issueSpec_value != NULL)
							{
								issueSpec = std::string((const char*) issueSpec_value);

								xmlFree(issueSpec_value);
							}
						}
						else if (xmlStrcasecmp(credential_info->name, (const xmlChar*) "IssuerPublicKey") == 0)
						{
							xmlChar* issuerIPK_value = xmlNodeListGetString(xmldoc, credential_info->xmlChildrenNode, 1);

							if (issuerIPK_value != NULL)
							{
								issuerIPK = std::string((const char*) issuerIPK_value);

								xmlFree(issuerIPK_value);
							}
						}
						else if (xmlStrcasecmp(credential_info->name, (const xmlChar*) "IssuerPrivateKey") == 0)
						{
							xmlChar* issuerISK_value = xmlNodeListGetString(xmldoc, credential_info->xmlChildrenNode, 1);

							if (issuerISK_value != NULL)
							{
								issuerISK = std::string((const char*) issuerISK_value);

								xmlFree(issuerISK_value);
							}
						}

						credential_info = credential_info->next;
					}

					if (issueSpec.empty() || issuerIPK.empty() || issuerISK.empty())
					{
						return;
					}

					issue_specs.push_back(issueSpec);
					issuer_ipks.push_back(issuerIPK);
					issuer_isks.push_back(issuerISK);

					atLeastOneCredSpec = true;
				}
				
				credentials = credentials->next;
			}
		}
		
		child_elem = child_elem->next;
	}
	
	xmlFreeDoc(xmldoc);
	
	is_valid = userPIN_set && atLeastOneCredSpec;
}

bool silvia_issuescript::valid()
{
	return is_valid;
}

std::string& silvia_issuescript::get_description()
{
	assert(is_valid == true);

	return description;
}

std::string& silvia_issuescript::get_user_PIN()
{
	assert(is_valid == true);

	return userPIN;
}

std::vector<std::string>& silvia_issuescript::get_issue_specs()
{
	assert(is_valid == true);

	return issue_specs;
}

std::vector<std::string>& silvia_issuescript::get_issuer_ipks()
{
	assert(is_valid == true);

	return issuer_ipks;
}

std::vector<std::string>& silvia_issuescript::get_issuer_isks()
{
	assert(is_valid == true);

	return issuer_isks;
}

