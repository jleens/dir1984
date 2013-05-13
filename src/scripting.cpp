/* Copyright (c) 2010, Jerome S. Leens
* All rights reserved.
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
*     * Redistributions of source code must retain the above copyright
*       notice, this list of conditions and the following disclaimer.
*     * Redistributions in binary form must reproduce the above copyright
*       notice, this list of conditions and the following disclaimer in the
*       documentation and/or other materials provided with the distribution.
*     * Neither the name of Jerome S. Leens nor the
*       names of its contributors may be used to endorse or promote products
*       derived from this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS ``AS IS'' 
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER AND CONTRIBUTORS BE LIABLE 
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER 
* CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, 
* OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "scripting.h"

__u32 name_to_mask(char *name)
{
	if(strcmp(name,"ACCESS")==0)
	{
		return IN_ACCESS;
	}
	if(strcmp(name,"ATTRIB")==0)
	{
		return IN_ATTRIB;
	}
	if(strcmp(name,"CLOSE_WRITE")==0)
	{
		return IN_CLOSE_WRITE;
	}
	if(strcmp(name,"CLOSE_NOWRITE")==0)
	{
		return IN_CLOSE_NOWRITE;
	}
	if(strcmp(name,"CREATE")==0)
	{
		return IN_CREATE;
	}
	if(strcmp(name,"DELETE")==0)
	{
		return IN_DELETE;
	}
	if(strcmp(name,"DELETE_SELF")==0)
	{
		return IN_DELETE_SELF;
	}
	if(strcmp(name,"MODIFY")==0)
	{
		return IN_MODIFY;
	}
	if(strcmp(name,"MOVE_SELF")==0)
	{
		return IN_MOVE_SELF;
	}
	if(strcmp(name,"MOVED_FROM")==0)
	{
		return IN_MOVED_FROM;
	}
	if(strcmp(name,"MOVED_TO")==0)
	{
		return IN_MOVED_TO;
	}
	if(strcmp(name,"OPEN")==0)
	{
		return IN_OPEN;
	}
	return (__u32)0;
}



char** scripts_for_event(vector<struct dir_script> v_scripts, struct script_execute bitmasks[EVENT_QTY])
{
	
	__u32 tmp_mask;
	
	// Variable scripts will contain the names of the scripts that will be used
	// Allocate memory
	
	char **scripts;
	scripts = (char**)malloc( v_scripts.size()* sizeof(char*));	
	// For each event, initialize the number of scripts to be launched
	// and allocate memory for the list of scrips_id.
	// What we call the script ID is the position of the script in script[]
	for(unsigned char i = 0; i < EVENT_QTY; i ++)
	{
		bitmasks[i].nbr_scripts = 0;
		bitmasks[i].scripts_id=(unsigned char*)malloc(sizeof(unsigned char)*v_scripts.size());	
	}
	
	// For each script, add the script name in scripts[]
	for(size_t i = 0 ; i < v_scripts.size(); i++)
	{
		scripts[i] = (char*) malloc (strlen(v_scripts[i].scriptname) * sizeof(char));
		strcpy(scripts[i],v_scripts[i].scriptname);
		tmp_mask = v_scripts[i].mask;
		
		// For each script, check which events are concerned
		// by checking if the last bit of the mask is 1
		// and shift right to select the next event
		for (unsigned char j=0 ; j < EVENT_QTY; j++)
		{
			if(tmp_mask%2)
			{
				bitmasks[j].scripts_id[bitmasks[j].nbr_scripts]=i;
				bitmasks[j].nbr_scripts++;
			}
			tmp_mask >>= 1;
		}
		//syslog(LOG_INFO,"SCRIPTNAME_%d_ %s",i,scripts[i]);
	}
	
//	scripts_names=scripts;
	return scripts;
}

__u32 get_events_to_watch(vector<struct dir_script> scripts)
{
	__u32 masque = IN_CREATE | IN_MOVED_TO;
	for(unsigned char i=0;i<scripts.size();i++)
	{
		masque = masque | scripts[i].mask;
	}
	return masque;
}

int mask_to_int(__u32 mask)
{
	//clean mask from its flags
	mask = mask & 0x00000FFF;
	switch(mask)
	{
		case 0x00000001 : return 0;
		case 0x00000002 : return 1;
		case 0x00000004 : return 2;
		case 0x00000008 : return 3;
		case 0x00000010 : return 4;
		case 0x00000020 : return 5;
		case 0x00000040 : return 6;
		case 0x00000080 : return 7;
		case 0x00000100 : return 8;
		case 0x00000200 : return 9;
		case 0x00000400 : return 10;
	}
	return -1;
}

