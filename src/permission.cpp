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

int change_permission(/*mode_t initial,*/char* command,vector<perm_infos>& masques)
{
	
	vector<perm_infos> masks;
	perm_infos pi_tmp;
//	mode_t perm_base = initial;
	char cur_op;
	char base=-1;
	char *perm[3];
	char *buffer=NULL;
	mode_t perm_curop;
	buffer = (char*)malloc(strlen(command)+1);
	strcpy(buffer,command);
	
	//get user permissions
	if((perm[0]=strtok(buffer," ,"))==NULL)
	 return -1;
	//get group permissions
	if((perm[1]=strtok(NULL," ,"))==NULL)
		return -2;
	//get others permissions
	if((perm[2]=strtok(NULL," ,"))==NULL)
		return -3;
		
		
	//printf("%s\t%s\t%s",perm[0],perm[1],perm[2]);
	
	for(int i=0;i<3;i++)
	{		
		base=-1;
		perm_curop=0;
		if(strlen(perm[i])>=1)
		{
			switch((char)perm[i][0])
			{
				//operation will remain = -1 if there is no + or -
				//character 
				case 'u':base=0;pi_tmp.operation=-1;break;
				case 'g':base=1;pi_tmp.operation=-1;break;	
				case 'o':base=2;pi_tmp.operation=-1;break;
				//if numeric permission, operation = -2
				case '0':base=i;
								 pi_tmp.operation=-2;
								 perm_curop=0;
								 break;
				case '1':base=i;
								 pi_tmp.operation=-2;
								 if(i==0) perm_curop = S_IXUSR;
								 if(i==1) perm_curop = S_IXGRP;
								 if(i==2) perm_curop = S_IXOTH;
								 break;
				case '2':base=i;pi_tmp.operation=-2;
								 if(i==0) perm_curop = S_IWUSR;
						     if(i==1) perm_curop = S_IWGRP;
						     if(i==2) perm_curop = S_IWOTH;
								 break;
				case '3':base=i;pi_tmp.operation=-2;
								 if(i==0) perm_curop = S_IXUSR|S_IWUSR;
								 if(i==1) perm_curop = S_IXGRP|S_IWGRP;
								 if(i==2) perm_curop = S_IXOTH|S_IWOTH;
								 break;
				case '4':base=i;pi_tmp.operation=-2;
								 if(i==0) perm_curop = S_IRUSR;
						     if(i==1) perm_curop = S_IRGRP;
						     if(i==2) perm_curop = S_IROTH;
								 break;
				case '5':base=i;pi_tmp.operation=-2;
								 if(i==0) perm_curop = S_IRUSR|S_IXUSR;
						     if(i==1) perm_curop = S_IRGRP|S_IXGRP;
						     if(i==2) perm_curop = S_IROTH|S_IXOTH;
								 break;
				case '6':base=i;pi_tmp.operation=-2;
								 if(i==0) perm_curop = S_IRUSR|S_IWUSR;
						     if(i==1) perm_curop = S_IRGRP|S_IWGRP;
						     if(i==2) perm_curop = S_IROTH|S_IWOTH;
								 break;
				case '7':base=i;pi_tmp.operation=-2;
								 if(i==0) perm_curop = S_IRUSR|S_IWUSR|S_IXUSR;
						     if(i==1) perm_curop = S_IRGRP|S_IWGRP|S_IXGRP;
						     if(i==2) perm_curop = S_IROTH|S_IWOTH|S_IXOTH;
								 break;
				default: return -4;
			}
		}
		
		cur_op=0;
		if(pi_tmp.operation !=-2)
		{
		for(unsigned int j=1;j<strlen(perm[i]);j++)
		{
			
			switch((char)perm[i][j])
			{
				// if addition, operation = 1
				case '+':
					if(cur_op!=0)
					{
						pi_tmp.target=i; //target = i (user/grp/others)
						pi_tmp.operation=cur_op; //cur_op = last_operation before +
						if(cur_op==2)
						{
							//if previous operation was -
							//then take the opposite bitfield
							perm_curop=perm_curop^XORINVERSE; 
						}
						//set perm_mask
						pi_tmp.perm_mask=perm_curop;
						//set the number of shifts (bit to move right or left
						// to align the target with the base (e.g. u=g+w, 
						// u is the target, g the base at which we add 'w' permission
						// *3 because permissions are coded on 3 bits (rwx)
						pi_tmp.shifts=(base-i)*3;
						//add the rule to vector
						masks.push_back(pi_tmp);
					}
					// set cur_op to +
					cur_op=1;perm_curop=0;break;
				case '-':
					if(cur_op!=0)
					{
						pi_tmp.target=i;
						pi_tmp.operation=cur_op;
						if(cur_op==2)
						{
							perm_curop=perm_curop^XORINVERSE;
						}
						pi_tmp.perm_mask=perm_curop;
						pi_tmp.shifts=(base-i)*3;
						masks.push_back(pi_tmp);
					}
					cur_op=2;perm_curop=0;break;
							
					//add read permission to mask
				case 'r':if(i==0) perm_curop = perm_curop | S_IRUSR;
						     if(i==1) perm_curop = perm_curop | S_IRGRP;
						     if(i==2) perm_curop = perm_curop | S_IROTH;
								 break;
								 //add write permission to mask
				case 'w':if(i==0) perm_curop = perm_curop | S_IWUSR;
						     if(i==1) perm_curop = perm_curop | S_IWGRP;
						     if(i==2) perm_curop = perm_curop | S_IWOTH;
								 break;
								 //add execute permission to mask
				case 'x':if(i==0) perm_curop = perm_curop | S_IXUSR;
						     if(i==1) perm_curop = perm_curop | S_IXGRP;
						     if(i==2) perm_curop = perm_curop | S_IXOTH;
						 		 break;
						 		 
					
				default:break;
				
			}
		}
		}
		if(cur_op>0)
		{
			pi_tmp.target=i;
			pi_tmp.operation=cur_op;
			if(cur_op==2)
	 		{
	 			perm_curop=perm_curop^XORINVERSE;
	 		}
	 		pi_tmp.perm_mask=perm_curop;
	 		pi_tmp.shifts=(base-i)*3;
	 		masks.push_back(pi_tmp);
	 		printf("element ajoute a %d\n",i);
	 	}
	 	else
	 	{
	 		pi_tmp.target=i;
	 		// if permission contains no operation
	 		// and if perm=u,g or o, mask = null
	 		if(pi_tmp.operation==-1)
	 			pi_tmp.perm_mask=0;
	 		else pi_tmp.perm_mask=perm_curop;
	 		pi_tmp.shifts=(base-i)*3;
	 		masks.push_back(pi_tmp);
	 	}
	}
	/*syslog(LOG_INFO, "elements: %d ", masks.size());
	
	for ( size_t i = 0, size = masks.size(); i < size; ++i )
  {
  	syslog(LOG_INFO, "%d shifts: %d ", i,masks[i].shifts);
  	syslog(LOG_INFO, "%d mask: %o, operation %d", i,masks[i].perm_mask,masks[i].operation);
       
  }*/
	masques = masks;
	return 0;
}

void apply_access(mode_t initial,vector<perm_infos> masks,mode_t *final)
{
	mode_t tmp=0;
	mode_t buf_initial;
	
	for ( size_t i = 0, size = masks.size(); i < size; ++i )
	{
			buf_initial = initial;
			switch(masks[i].operation)
			{
				//if permission is numeric, just apply the mask
				case (-2): tmp = tmp | masks[i].perm_mask; break;
				//if permission is u,g or o without any operation
				//we shift the original mode_t in order to align
				//the base and the target. Then we apply an AND 
				//between the shifted mode_t and a mode_t which is
				//composed of 0's and three 1's (the bits of the target)
				//in order to isolate the permission of owner, grpowner
				//or others.
				case (-1): 
					 if(masks[i].shifts>0)
						buf_initial = buf_initial << masks[i].shifts;
					 else buf_initial = buf_initial >> -(masks[i].shifts);
							 
					 if(masks[i].target==0)
					 	 tmp=tmp|(buf_initial & S_IRWXU);
					 if(masks[i].target==1)
					 	 tmp=tmp|(buf_initial & S_IRWXG);
					 if(masks[i].target==2)
					 	 tmp=tmp|(buf_initial & S_IRWXO);
					 
				 	 break;
				 	 
				case 1:  
				//if permission is u,g or o with an addition operation
				//we shift the original mode_t in order to align
				//the base and the target. Then we apply a OR between 
				//the shifted mode_t and the mask previously determined.
				//The mask is made of 0's except for the bits which must
				//be added. Then a AND is applied between the result of
				//this OR and a mode_t composed of 0's and three 1's
				//(see case -1)
					if(masks[i].shifts>0)
						buf_initial = buf_initial << masks[i].shifts;
					else buf_initial = buf_initial >> -(masks[i].shifts);
				//	syslog(LOG_INFO,"buf_initial apres shift + %o", buf_initial);
					if(masks[i].target==0)
					 	 tmp =tmp|((buf_initial | masks[i].perm_mask) & S_IRWXU);
					 if(masks[i].target==1)
					 	 tmp =tmp|((buf_initial | masks[i].perm_mask) & S_IRWXG);
					 if(masks[i].target==2)
					 	 tmp =tmp|((buf_initial | masks[i].perm_mask) & S_IRWXO);
					
					
					break;
				case 2:	 
				//if permission is u,g or o with a subtraction operation 
				//we shift the original mode_t in order to align the base
				//and the target. Then we apply an AND between the shifted mode_t
				//and the mask previously determined. The mask is made of 1's except
				//for the bits which must be removed. Then a AND is applied between
				//the result of the previous opération and a mode_t composed
				//of 0's and three 1's
					if(masks[i].shifts>0)
						buf_initial = buf_initial << masks[i].shifts;
					else buf_initial = buf_initial >> -(masks[i].shifts);
					
					if(masks[i].target==0)
					 	 tmp =tmp|((buf_initial & masks[i].perm_mask) & S_IRWXU);
					 if(masks[i].target==1)
					 	 tmp =tmp|((buf_initial & masks[i].perm_mask) & S_IRWXG);
					 if(masks[i].target==2)
					 	 tmp =tmp|((buf_initial & masks[i].perm_mask) & S_IRWXO);
					
					
					break;
				default: break;
			 	
			 	
			}
	/*		syslog(LOG_INFO, "%d apply_access: tmp = %o ",i, tmp);
       printf("%d ",masks[i].shifts);*/
  }
  // In order to keep the flags of the original mode_t, located at the beginning
  // of mode_t, we make a logical AND between the original mode_t and a mode_t
  // made of 1's except for the bits used for user, group and others' permissions
  // The result of this and is then added to the estimated mask
	tmp =tmp| (initial & KEEPFLAGS);
	//syslog(LOG_INFO, "final apply_access: tmp = %o KEEPFLAGS %o", tmp,KEEPFLAGS);
	*final = tmp;
}

