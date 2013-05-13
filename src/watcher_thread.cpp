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


#include "watcher_thread.h"



// Main Function of threads
void *access_change(void *par)
{
	int t;
	mode_t droits_acces;
	struct param *p ;
	p=(struct param*) par;
	char *panzer;
	vector<char*> mateurs(1000);
	FILE *cmd; FILE *script_pipe;
	int fd, wd;
	struct passwd *pwd;
	struct group *grp;
	char buf[BUF_LEN],ligne[CHAR_SIZE];
	int len,event_int,i=0;
	__u32 events_to_monitor;
	char **scripts=NULL;
	
	struct script_execute sc_execute[EVENT_QTY];
	
	uid_t userid=-1;
	gid_t grpid=-1;
	char tmp[BUF_LEN/2];
	
	
	struct stat statfile;
	
	
	scripts=scripts_for_event(p->scripts, sc_execute);	
	events_to_monitor=get_events_to_watch(p->scripts);
	
	//init inotify
	fd = inotify_init();
	
	if (fd < 0)
		perror("inotify_init");
		
	
	//syslog(LOG_INFO,"thread %s: nombre de scripts: %d",p->dossier,p->scripts.size());
	/*for(unsigned char a=0;a<p->scripts.size();a++)
	{
		syslog(LOG_INFO,"thread %s: masque:%u",p->dossier,p->scripts[a].mask);
	}*/
	if(p->recursive ==1)
	{
		//we call the following script through a pipe open and
		//get the result: the list of all subdirectories of the
		//one we have to watch
		sprintf(tmp,"bash /etc/dir1984/getdirs.sh %s",p->dossier);
		cmd=popen(tmp,"r");
	
		//Add a watch to each subdirectory
		while(fgets(ligne,sizeof(ligne),cmd)!=NULL)
		{
	
			ligne[strlen(ligne)-1]=0;
			wd = inotify_add_watch(fd,ligne,events_to_monitor);//IN_CREATE|IN_MOVED_TO);
			if (wd < 0)
			{
				perror("inotify_add_watch");
				syslog(LOG_INFO,"%s Error: inotify_add_watch %s",DAEMON_NAME,ligne);
			}
			else
			{
				panzer=(char*)malloc(strlen(ligne)+1);
				strncpy(panzer,ligne,strlen(ligne)+1);
				mateurs[wd]=panzer;		
				syslog(LOG_INFO,"inotify_add_watch %s OK",panzer);
	
			}
			
		}
		pclose(cmd);
	}
	else 
	{
		//add watch to the directory
		wd= inotify_add_watch(fd,p->dossier,events_to_monitor);//IN_CREATE|IN_MOVED_TO);
		if (wd < 0)
		{
			perror("inotify_add_watch");printf("%d %s\n",wd,ligne);
			syslog(LOG_INFO,"%s Error: inotify_add_watch %s",DAEMON_NAME,ligne);
		}
		else
		{
			panzer=(char*)malloc(strlen(p->dossier)+1);
			strncpy(panzer,p->dossier,strlen(p->dossier)+1);
			mateurs[wd]=panzer;
		}
	}
	// if userowner is not set, we won't change it
	if(strcmp(p->userowner,".")!=0)
	{
		//get pwd struct related to the chosen user
		if((pwd=getpwnam(p->userowner))==NULL)
		{
			syslog(LOG_INFO,"%d User %s unknown",t,p->userowner);
		}
		else
		{
		//if user exists, we get his id
			syslog(LOG_INFO,"%s files will be given to user %s id:%d",p->dossier,p->userowner,pwd->pw_uid);	
			userid=(pwd->pw_uid);
		}
	}
			
	// we do the same for group as we did for user.
	if(strcmp(p->grpowner,".")!=0)
	{
		if((grp=getgrnam(p->grpowner))==NULL)
		{
			syslog(LOG_INFO,"Group %s unknown",p->grpowner);
		}
		else
		{
			syslog(LOG_INFO,"%s files will be given to group %s grid:%d",p->dossier,p->grpowner,grp->gr_gid);
			grpid= (grp->gr_gid);
		}
	}
	
	while(0==0)
	{
		len = read(fd,buf,BUF_LEN);
		if(len<=0) printf("len = %d\n",len);
		i=0;
		//get inotify events
		while(i<len)
		{
			struct inotify_event *event;
			event = (struct inotify_event*) &buf[i];
			
			if(event->len)
		//	syslog(LOG_INFO,"evenement: %d",event->mask);
				printf("name=%s\n", event->name);
			
		
			
			sprintf(tmp,"%s/%s",mateurs[event->wd],event->name);
			
			
			
			//get stat struct for the file that provoked the event
			if(stat(tmp,&statfile)==0)
			{
				// If the new file is actually a directory
				// we add a watcher for this directory
				if(S_ISDIR(statfile.st_mode) && p->recursive==1)
				{
					wd = inotify_add_watch(fd,tmp,events_to_monitor);//IN_CREATE|IN_MOVED_TO);
					if (wd < 0)
					{
						perror("inotify_add_watch");
						syslog(LOG_INFO,"Error: inotify_add_watch for newly created: %s",tmp);	
					}
					else
					{
						panzer=(char*)malloc(strlen(tmp)+1);
						strncpy(panzer,tmp,strlen(tmp)+1);
						mateurs[wd]=panzer;
					}
				}
				//apply permission rules for new file
				// !!!! ONLY FOR CREATE AND MOVED_TO EVENTS
				if(mask_to_int(event->mask)==7 || mask_to_int(event->mask)==8)
				{
					apply_access(statfile.st_mode,p->masks,&droits_acces);
					//syslog(LOG_INFO,"NOUVEAU DROIT ACCESS %s %d",tmp,droits_acces);
					chmod(tmp,droits_acces);
				}
	
			}
			//change owner and grp owner of the new file
			chown(tmp,userid,grpid);
				
			
			if((event_int=mask_to_int(event->mask))>=0)
			{
				//run each script for the event type that occured
				for(int a=0; a<sc_execute[event_int].nbr_scripts;a++)
				{
					//run script
					script_pipe=popen(scripts[sc_execute[event_int].scripts_id[a]],"r");
					//close pipe
					pclose(script_pipe);
				}
			}
			
			
			i+= EVENT_SIZE + event->len;
			
		}
		
	}

	pthread_exit(NULL);

}
