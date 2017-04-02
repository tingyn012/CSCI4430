# include <stdio.h>
# include <stdlib.h>
# include <unistd.h>
# include <string.h>
# include <errno.h>
# include <dirent.h>
# include <fcntl.h>
# include <pthread.h>
# include <sys/stat.h>
# include <sys/socket.h>
# include <sys/types.h>
# include <sys/sendfile.h>
# include <netinet/in.h>

# define PORT 12345
# define true 1
# define false 0

struct message_s {
unsigned char protocol[6]; /* protocol magic number (6 bytes) */
unsigned char type; /* type (1 byte) */
unsigned char status; /* status (1 byte) */
unsigned int length; /* length (header + payload) (4 bytes) */
} __attribute__ ((packed));

struct message_s Reply;

int auth(unsigned char* buff,int len){
	FILE* fp;
	int j;
	fp=fopen("access.txt","r");
	char* read = malloc(65);
	if(!fp){
		printf("Can't open access.txt!\n");
		return false;
	}

	while(fgets(read,65,fp) > 0){
		if(strcmp(buff,read) == 0){
		return 1;
		}
	}

	return 0;
}

char* ls(char* lsbuffer){
    DIR *dir;
    struct dirent * ptr;
    dir = opendir(".");
	if(!dir){
		printf("dir\n");
		return 0;
	}
	while((ptr = readdir(dir))!=NULL) {
		if(ptr->d_type == 8){ //regular file
			strcat(lsbuffer,ptr->d_name);
			strcat(lsbuffer,"\n");
		}
      //  sprintf(pathname,"%s\n", );
    }
	// printf("\n%s",lsbuffer);
    closedir(dir);

	return lsbuffer;
}

void OCReply(){
	Reply.protocol[0] = 0xe3;
	Reply.protocol[1] = 'm';
	Reply.protocol[2] = 'y';
	Reply.protocol[3] = 'f';
	Reply.protocol[4] = 't';
	Reply.protocol[5] = 'p';
	Reply.type = 0xA2;
	Reply.status = 1;
	Reply.length = 12;
}

void AuthReplyS(){
	Reply.protocol[0] = 0xe3;
	Reply.protocol[1] = 'm';
	Reply.protocol[2] = 'y';
	Reply.protocol[3] = 'f';
	Reply.protocol[4] = 't';
	Reply.protocol[5] = 'p';
	Reply.type = 0xA4;
	Reply.status = 1;
	Reply.length = 12;
}

void AuthReplyF(){
	Reply.protocol[0] = 0xe3;
	Reply.protocol[1] = 'm';
	Reply.protocol[2] = 'y';
	Reply.protocol[3] = 'f';
	Reply.protocol[4] = 't';
	Reply.protocol[5] = 'p';
	Reply.type = 0xA4;
	Reply.status = 0;
	Reply.length = 12;
}

void *start_routine(int client_sd){
	while(1){
     //   printf("BEFORE RECV\n");
		char *buff = malloc(1024);
		int len;
		if((len=recv(client_sd,buff,sizeof(struct message_s),0))<=0){
			printf("receive error: %s (Errno:%d)\n", strerror(errno),errno);
			pthread_exit(NULL);
		}

		OCReply();

    //    printf("AFTER RECV\n");

		struct message_s *be = malloc(sizeof(struct message_s));
		memcpy(be,buff,12);

	//	printf("RECEIVED INFO:\n");
	
		if(be->type == 0xA1){
			if((len=send(client_sd,&Reply,sizeof(struct message_s),0))<=0){
				printf("Send Error: %s (Errno:%d)\n",strerror(errno),errno);
			}		
		}

		if(be->type == 0xA3){
			memset(buff,0,1024);
			if((len=recv(client_sd,buff,1024,0))<=0){
				printf("receive error: %s (Errno:%d)\n", strerror(errno),errno);
				pthread_exit(NULL);
			}
			buff[len]='\0';
	//		printf("buff:%s len:%d\n",buff,len);
	//		int i;
	//		for(i=1;i<len;i++){
	//			printf("%d ",buff[i]);
	//		}
			if(auth(buff,len) == 1){
				AuthReplyS();
				if((len=send(client_sd,&Reply,sizeof(struct message_s),0))<=0){
					printf("Send Error: %s (Errno:%d)\n",strerror(errno),errno);
				}
			} else {
				AuthReplyF();
				if((len=send(client_sd,&Reply,sizeof(struct message_s),0))<=0){
					printf("Send Error: %s (Errno:%d)\n",strerror(errno),errno);
				}
			}
		}

		if(be->type == 0xA5){
			char* lsbuffer = malloc(4096);
			lsbuffer = ls(lsbuffer);
	//		printf("=======\n");
	//		int i = 0;
	//		for(i;i<strlen(lsbuffer);i++){
	//		printf("%d ",lsbuffer[i]);
	//		}
	//		printf("\n=======\n");
			Reply.protocol[0] = 0xe3;
			Reply.protocol[1] = 'm';
			Reply.protocol[2] = 'y';
			Reply.protocol[3] = 'f';
			Reply.protocol[4] = 't';
			Reply.protocol[5] = 'p';
			Reply.type = 0xA6;
			Reply.status = 0;
			Reply.length = 13+strlen(lsbuffer);
			if((len=send(client_sd,&Reply,sizeof(struct message_s),0))<=0){
				printf("Send Error: %s (Errno:%d)\n",strerror(errno),errno);
			}
			if((len=send(client_sd,lsbuffer,strlen(lsbuffer)+1,0))<=0){
				printf("Send Error: %s (Errno:%d)\n",strerror(errno),errno);
			}
			free(lsbuffer);
			//printf("lsbuffer:%d\n",strlen(lsbuffer));
		}


		/* Get Command */
		if(be->type == 0xA7){
	//		printf("Here......\n");
			if((len=recv(client_sd,buff,1024,0))<=0){
				printf("receive error: %s (Errno:%d)\n", strerror(errno),errno);
				pthread_exit(NULL);
			}
			buff[len]='\0';
	//		printf("%s\n",buff);

			char path[1024];
			char currPath[1024];
			char *exist;  
			exist=realpath(buff, path);
			if(exist == NULL){
				printf("Not exist!!\n");
			}

			int fd;           /* file descriptor for file to send */
			off_t offset = 0; /* file offset */
			struct stat stat_buf;      /* argument to fstat */
			int rc;                    /* holds return code of system calls */

			Reply.protocol[0] = 0xe3;
			Reply.protocol[1] = 'm';
			Reply.protocol[2] = 'y';
			Reply.protocol[3] = 'f';
			Reply.protocol[4] = 't';
			Reply.protocol[5] = 'p';
			Reply.type = 0xA8;
			Reply.status = 1;
			Reply.length = 12;

	//		printf("Realpath:%s\n",path);
			realpath(".", currPath);
	//		printf("currPath:%s\n",currPath);
			if(memcmp(path,currPath,strlen(currPath)) != 0){
				Reply.status = 0;
				if((len=send(client_sd,&Reply,sizeof(struct message_s),0))<=0){
					printf("Send Error: %s (Errno:%d)\n",strerror(errno),errno);
				}
				continue;
			}

			fd = open(path, O_RDONLY);
			if (fd == -1) {
				fprintf(stderr, "unable to open '%s': %s\n", path, strerror(errno));
				Reply.status = 0;
			}

			fstat(fd, &stat_buf);
			//printf("Size:%d",stat_buf.st_size);

			// Reply.length = 13+stat_buf.st_size;
	//		printf("%d",S_ISREG(stat_buf.st_mode));


			if(S_ISREG(stat_buf.st_mode) == 0){
				Reply.status = 0;
				fd = -1;
			}


			if((len=send(client_sd,&Reply,sizeof(struct message_s),0))<=0){
				printf("Send Error: %s (Errno:%d)\n",strerror(errno),errno);
			}

			if (fd == -1) {
				continue;
			}

			Reply.type = 0xAA;
			Reply.status = 1;
			Reply.length = 12+stat_buf.st_size;

			if((len=send(client_sd,&Reply,sizeof(struct message_s),0))<=0){
				printf("Send Error: %s (Errno:%d)\n",strerror(errno),errno);
			}

			/* copy file using sendfile */
			offset = 0;
			rc = sendfile(client_sd, fd, &offset, stat_buf.st_size);
			if (rc == -1) {
			  fprintf(stderr, "error from sendfile: %s\n", strerror(errno));
			  exit(1);
			}
			if (rc != stat_buf.st_size) {
			  fprintf(stderr, "incomplete transfer from sendfile: %d of %d bytes\n",rc,(int)stat_buf.st_size);
			  exit(1);
			}

			/* close descriptor for file that was sent */
			close(fd);

		}

		/* Put Command */
		if(be->type == 0xA9){
	//		printf("Here A9 *%d*\n",be->length-13);
			Reply.protocol[0] = 0xe3;
			Reply.protocol[1] = 'm';
			Reply.protocol[2] = 'y';
			Reply.protocol[3] = 'f';
			Reply.protocol[4] = 't';
			Reply.protocol[5] = 'p';
			Reply.type = 0xAA;
			Reply.status = 1;
			Reply.length = 12;

			if((len=recv(client_sd,buff,sizeof(struct message_s),0))<=0){
				printf("receive error: %s (Errno:%d)\n", strerror(errno),errno);
				exit(0);
			}
			buff[len]='\0';
	//		printf("%s\n",buff);

			FILE *fp = fopen(buff, "wb+");

			if((len=send(client_sd,&Reply,sizeof(struct message_s),0))<=0){
				printf("Send Error: %s (Errno:%d)\n",strerror(errno),errno);
			}

			if((len=recv(client_sd,buff,sizeof(struct message_s),0))<=0){
				printf("receive error: %s (Errno:%d)\n", strerror(errno),errno);
				exit(0);
			}

			memcpy(be,buff,12);
			be->length = be->length - 12;

			if((len=recv(client_sd,buff,1024,0))<=0){
				printf("receive error: %s (Errno:%d)\n", strerror(errno),errno);
			}

			while(len >= 1024){
			//	printf("@%d \n",be->length);
				fwrite(buff,1024,1,fp);
				be->length = be->length - 1024;
				if(be->length >= 1024){
					if((len=recv(client_sd,buff,1024,0))<=0){
						printf("receive error: %s (Errno:%d)\n", strerror(errno),errno);
					}
			//		printf("@len%d \n",len);
				} else {
					if((len=recv(client_sd,buff,be->length,0))<=0){
						printf("receive error: %s (Errno:%d)\n", strerror(errno),errno);
					}
			//		printf("#len%d \n",len);
				}
			}

	//			printf("!%d \n",be->length);

			if(be->length >= 1024){
				printf("Receive error.Thread exit.\n");
				pthread_exit(NULL);
			}

			fwrite(buff,be->length,1,fp);
			fclose(fp);
			printf("Downloaded\n");


		}

		if(strcmp("exit",buff)==0){
			close(client_sd);
			break;		
	    }

		if(be->type == 0xAB){
			Reply.protocol[0] = 0xe3;
			Reply.protocol[1] = 'm';
			Reply.protocol[2] = 'y';
			Reply.protocol[3] = 'f';
			Reply.protocol[4] = 't';
			Reply.protocol[5] = 'p';
			Reply.type = 0xAC;
			Reply.status = 1;
			Reply.length = 12;
			if((len=send(client_sd,&Reply,sizeof(struct message_s),0))<=0){
				printf("Send Error: %s (Errno:%d)\n",strerror(errno),errno);
			}
			printf("Exit.\n");
			pthread_exit(NULL);
		}

		free(be);

	}
}

int main(int argc, char** argv){
	int sd=socket(AF_INET,SOCK_STREAM,0);
	int client_sd;

	struct sockaddr_in server_addr;
	memset(&server_addr,0,sizeof(server_addr));
	server_addr.sin_family=AF_INET;
	server_addr.sin_addr.s_addr=htonl(INADDR_ANY);
	server_addr.sin_port=htons(PORT);
	if(bind(sd,(struct sockaddr *) &server_addr,sizeof(server_addr))<0){
		printf("bind error: %s (Errno:%d)\n",strerror(errno),errno);
		exit(0);
	}
	if(listen(sd,3)<0){
		printf("listen error: %s (Errno:%d)\n",strerror(errno),errno);
		exit(0);
	}
	struct sockaddr_in client_addr;
	int addr_len=sizeof(client_addr);
	/*if((client_sd=accept(sd,(struct sockaddr *) &client_addr,&addr_len))<0){
		printf("accept erro: %s (Errno:%d)\n",strerror(errno),errno);
		exit(0);
	}*/
	while(1){
	//	printf("BEFORE ACCEPT\n");
		if((client_sd=accept(sd,(struct sockaddr *) &client_addr,&addr_len))<0){
			printf("accept erro: %s (Errno:%d)\n",strerror(errno),errno);
			exit(0);
		}else{
		    printf("receive connection from %s\n",inet_ntoa(client_addr.sin_addr.s_addr));
		}
	//	printf("AFTER ACCEPT\n");

		pthread_t thread;
		int rc = pthread_create(&thread,NULL,start_routine, (void *)client_sd);
	}


	close(sd);
	return 0;
}
