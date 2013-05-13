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

#include "permission.h"
#include "watcher_thread.h"
#include "scripting.h"
#define DEFAULT_EVENTS IN_CREATE|IN_MOVED_TO

using namespace std;


int main()
{
	int rc,i;
	unsigned char cpt;
	FILE *config;	
	pthread_t thread[32];
	char ligne[CHAR_SIZE];
	char *dossier, *userowner, *grpowner, *access, *ptr, *ptr_tmp, *event, *ptr_tmp_bak;
	vector<struct dir_script> v_scripts(0);
	__u32 masque=0;
	
	pid_t pid,sid;
	// Fork parent process
	pid = fork();
	if(pid<0)
		exit(EXIT_FAILURE);
	
	//If pid OK -> exit the parent process
	if (pid>0)
		exit(EXIT_SUCCESS);
		
	umask(0);
	
	//Create sid for child process
	sid = setsid();
	if(sid <0)
	{	
		exit(EXIT_FAILURE);
	}
	//Close standard file descriptors
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	
	
	syslog(LOG_INFO, "%s daemon starting up", DAEMON_NAME);
	
	config = fopen("/etc/dir1984/dir1984.conf","r");
	if(config!=NULL)
	{

		i=0;
		while(! feof(config))
		{
			fgets(ligne,sizeof(ligne),config);
	       
			dossier = strtok(ligne," ");
			if(dossier[0]!='#')
			{
				userowner = strtok(NULL," ");
				grpowner = strtok(NULL," ");
				access= strtok(NULL," ");
				if(!userowner || !grpowner || !access || !dossier) break;
				 
				
				cpt=0;
				ptr = strtok(NULL," ");
				while(ptr!=NULL)
				{
					
					syslog(LOG_INFO,"vector size %d   ptr %s taille %d",v_scripts.size(),ptr,strlen(ptr));
					
					if(v_scripts.size()<=cpt)
						v_scripts.resize(cpt+1);
					syslog(LOG_INFO,"vector  new size %d",v_scripts.size());
					
					if((ptr_tmp=strchr(ptr,'|'))!=NULL)
					{
						
						strncpy(v_scripts[cpt].scriptname,ptr,ptr_tmp-ptr);
						v_scripts[cpt].scriptname[ptr_tmp-ptr]=0;
						//scriptname contains the name of the script to be launched
						
						event = (char*) malloc(strlen(ptr_tmp)+1);
						strncpy(event,ptr_tmp,strlen(ptr_tmp));
						event[strlen(ptr_tmp)]=0;
						ptr_tmp_bak = ptr_tmp;
						while((ptr_tmp=strchr(ptr_tmp,'|'))!=NULL)
						{
							ptr_tmp++;
							strncpy(event,ptr_tmp_bak,ptr_tmp-ptr_tmp_bak);
							event[ptr_tmp-ptr_tmp_bak-1]=0;
							//event contains the event name
							
							if(strlen(event)>0)
								masque = masque | name_to_mask(event);
						
							ptr_tmp_bak = ptr_tmp;
						}
						//the last event name is stored in ptr_tmp_bak
						//the following if/else is supposed to resolve
						//Carriage return/Line Feed issues
						if (ptr_tmp_bak[strlen(ptr_tmp_bak)-1]==10)
							ptr_tmp_bak[strlen(ptr_tmp_bak)-1]=0;
						else ptr_tmp_bak[strlen(ptr_tmp_bak)]=0;
						masque = masque | name_to_mask(ptr_tmp_bak);
						
						free(event);
						v_scripts[cpt].mask=masque;
					
						masque=0;
					}
					else
					{
						strcpy(v_scripts[cpt].scriptname,ptr);
						v_scripts[cpt].mask=DEFAULT_EVENTS;
					}
					
				
				
					cpt++;
					ptr = strtok(NULL," ");
				}
				
				
				struct param *p;
				p = (struct param*)malloc(sizeof(struct param));
				
				if(dossier[0]=='-' && dossier[1]=='R')
				 {
				    p->recursive=1;
				    dossier++;dossier++;
				 }
				 else p->recursive=0;
				
				 
				
				 
				
				strncpy(p->dossier,dossier,strlen(dossier));
					p->dossier[strlen(dossier)]=0; 					
				strncpy(p->userowner,userowner,strlen(userowner));
					p->userowner[strlen(userowner)]=0;
				strncpy(p->grpowner,grpowner,strlen(grpowner));
					p->grpowner[strlen(grpowner)]=0;
				strncpy(p->access,access,strlen(access));
					p->access[strlen(access)]=0;
					
					
				p->identifiant=i;
				
				
				syslog(LOG_INFO,"%s ACCESS TO GIVE %sL",p->dossier,p->access);
				
				change_permission(access,p->masks);
				 p->scripts=v_scripts;
				 v_scripts=vector<struct dir_script>(0);
				 
				//Create the thread related to the directory to monitor
				rc=pthread_create(&thread[i],NULL,access_change,(void*)p);
				
				if (rc){
					printf("ERROR; return code from pthread_create() is %d\n", rc);
					return -1;
				}
				i++;
			}
		}
	}
	else 
	{
		syslog(LOG_INFO,"%s Error: could not find configuration file",DAEMON_NAME);
		exit(0);
	}
	
	pthread_join(thread[0],NULL);
	
	return 0;
}

