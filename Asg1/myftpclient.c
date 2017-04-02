# include <stdio.h>
# include <stdlib.h>
# include <unistd.h>
# include <string.h>
# include <errno.h>
# include <dirent.h>
# include <fcntl.h>
# include <sys/stat.h>
# include <sys/socket.h>
# include <sys/types.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <sys/sendfile.h>

# define true 1
# define false 0

struct message_s {
unsigned char protocol[6]; /* protocol magic number (6 bytes) */
unsigned char type; /* type (1 byte) */
unsigned char status; /* status (1 byte) */
unsigned int length; /* length (header + payload) (4 bytes) */
} __attribute__ ((packed));

struct message_s OCRequest;

int aaa(char* buff,int len){
	int i;
	printf("len:%d\n",len);
	for(i=0;i<len;i++){
	printf("%c",buff[i]);
	}
	return 0;
}
void setOCRequest(){
	OCRequest.protocol[0] = 0xe3;
	OCRequest.protocol[1] = 'm';
	OCRequest.protocol[2] = 'y';
	OCRequest.protocol[3] = 'f';
	OCRequest.protocol[4] = 't';
	OCRequest.protocol[5] = 'p';
	OCRequest.type = 0xA1;
	OCRequest.status = 0;
	OCRequest.length = 12;
}

struct message_s setAUTH_REQUEST(struct message_s AUTH_REQUEST,char* id,char* password){
	char* result = malloc(65);
	strcpy(result,id);
	strcat(result," ");
	strcat(result,password);

//	AUTH_REQUEST.payload = malloc(strlen(result)+1);
	AUTH_REQUEST.protocol[0] = 0xe3;
	AUTH_REQUEST.protocol[1] = 'm';
	AUTH_REQUEST.protocol[2] = 'y';
	AUTH_REQUEST.protocol[3] = 'f';
	AUTH_REQUEST.protocol[4] = 't';
	AUTH_REQUEST.protocol[5] = 'p';
	AUTH_REQUEST.type = 0xA3;
	AUTH_REQUEST.status = 0;
	AUTH_REQUEST.length = 12+strlen(result)+1;
	//strcpy(AUTH_REQUEST.payload,result);

	free(result);

	return AUTH_REQUEST;
}

int main(int argc, char** argv){
	char input[256];
	char *token[10];
	int token_num;
	int accepted = false;
	int logined = false;
	int sd=socket(AF_INET,SOCK_STREAM,0);
	int len;
	char *buff = malloc(1024);
	struct sockaddr_in server_addr;

	while(1){
		token_num = 0;
		printf("Client> ");
		fgets (input, 256, stdin);
		if(input[0] != '\n'){
		token[0] = strtok(input, " \n");
		}
		while(token[token_num] != NULL){
			token[token_num + 1] = strtok(NULL, " ");
			token_num++;
		}

		if(strcmp(token[0],"open") == 0){
			if(token_num != 3){
				printf("Invaild command line. Usage: open <IP address> <port>\n");
				continue;
			}
			if(accepted == false){
				memset(&server_addr,0,sizeof(server_addr));
				server_addr.sin_family=AF_INET;
				server_addr.sin_addr.s_addr=inet_addr((char *)token[1]);
				server_addr.sin_port=htons(atoi(token[2]));
				if(connect(sd,(struct sockaddr *)&server_addr,sizeof(server_addr))<0){
					printf("connection error: %s (Errno:%d)\n",strerror(errno),errno);
					continue;
				}

				setOCRequest();

				if((len=send(sd,&OCRequest,OCRequest.length,0))<=0){
					printf("Send Error: %s (Errno:%d)\n",strerror(errno),errno);
					exit(0);
				}

				if((len=recv(sd,buff,1024,0))>=0){

					struct message_s *be = malloc(sizeof(struct message_s));
					memcpy(be,buff,12);
					if(be->protocol[0] != 0xe3 || memcmp((char *)&be->protocol[1],"myftp",5) != 0){
						printf("Unknown protocol message recieved, program exit.\n");
						exit(0);
					}

					printf("Server connection accepted.\n");
					accepted = true;		
				}

			} else {
				printf("Alreday in a connection.\n");
			}
		}

		if(strcmp(token[0],"auth") == 0){
			if(token_num != 3){
				printf("Invaild command line. Usage: auth <id> <password>\n");
				continue;
			}
			if(strlen(token[1]) > 32 || strlen(token[2]) > 32){
				printf("ID or password larger than 32 bytes.\n");
				continue;
			}
			if(accepted == true){
				struct message_s AUTH_REQUEST;
				AUTH_REQUEST = setAUTH_REQUEST(AUTH_REQUEST,token[1],token[2]);

				char* result = malloc(65);
				strcpy(result,token[1]);
				strcat(result," ");
				strcat(result,token[2]);

				if((len=send(sd,&AUTH_REQUEST,sizeof(struct message_s),0))<=0){
					printf("Send Error: %s (Errno:%d)\n",strerror(errno),errno);
					exit(0);
				}
				if((len=send(sd,result,strlen(result),0))<=0){
					printf("Send Error: %s (Errno:%d)\n",strerror(errno),errno);
					exit(0);
				}


				if((len=recv(sd,buff,1024,0))>=0){
					struct message_s *be = malloc(sizeof(struct message_s));
					memcpy(be,buff,12);
					if(be->protocol[0] != 0xe3 || memcmp((char *)&be->protocol[1],"myftp",5) != 0){
						printf("Unknown protocol message recieved, program exit.\n");
						exit(0);
					}

					if(buff[7] == 1){
						printf("Authentication granted.\n");
						logined = true;
					} else {
						printf("ERROR: Authentication rejected. Connection closed.\n");
						accepted = false;
						logined = false;
						close(sd);
						sd=socket(AF_INET,SOCK_STREAM,0); /* update new socket */
					}	
				}
			} else {
				printf("Not opened yet!\n");
			}

		}

		if(strcmp(token[0],"ls") == 0){
			if(token_num != 1){
				printf("Invaild command line. Usage: ls\n");
				continue;
			}
			if(logined == true){
				struct message_s LIST_REQUEST;
				LIST_REQUEST.protocol[0] = 0xe3;
				LIST_REQUEST.protocol[1] = 'm';
				LIST_REQUEST.protocol[2] = 'y';
				LIST_REQUEST.protocol[3] = 'f';
				LIST_REQUEST.protocol[4] = 't';
				LIST_REQUEST.protocol[5] = 'p';
				LIST_REQUEST.type = 0xA5;
				LIST_REQUEST.status = 0;
				LIST_REQUEST.length = 12;

				if((len=send(sd,&LIST_REQUEST,LIST_REQUEST.length,0))<=0){
					printf("Send Error: %s (Errno:%d)\n",strerror(errno),errno);
					exit(0);
				}

				if((len=recv(sd,buff,sizeof(struct message_s),0))>=0){
					struct message_s *be = malloc(sizeof(struct message_s));
					memcpy(be,buff,12);
					if(be->protocol[0] != 0xe3 || memcmp((char *)&be->protocol[1],"myftp",5) != 0){
						printf("Unknown protocol message recieved, program exit.\n");
						exit(0);
					}

					if((unsigned char )buff[6] == 0xA6){
							printf("----- file list start -----\n");
							if((len=recv(sd,buff,1024,0))>=0){
							buff[len]='\0';
							printf("%s",buff);
							}else {
							printf("receive error: %s (Errno:%d)\n", strerror(errno),errno);
							exit(0);
							}
							printf("----- file list end -----\n");
						}
				} else {
					printf("receive error: %s (Errno:%d)\n", strerror(errno),errno);
					exit(0);
				}
			} else {
				printf("Not logined yet!\n");
			}
		}

		if(strcmp(token[0],"get") == 0){

			if(token_num != 2){
				printf("Invaild command line. Usage: get <file name>\n");
				continue;
			}

			if(logined == true){
				struct message_s GET_REQUEST;
				GET_REQUEST.protocol[0] = 0xe3;
				GET_REQUEST.protocol[1] = 'm';
				GET_REQUEST.protocol[2] = 'y';
				GET_REQUEST.protocol[3] = 'f';
				GET_REQUEST.protocol[4] = 't';
				GET_REQUEST.protocol[5] = 'p';
				GET_REQUEST.type = 0xA7;
				GET_REQUEST.status = 0;
				GET_REQUEST.length = 12+strlen(token[1])+1;

				if((len=send(sd,&GET_REQUEST,12,0))<=0){
					printf("Send Error: %s (Errno:%d)\n",strerror(errno),errno);
					exit(0);
				}

				if((len=send(sd,token[1],strlen(token[1]+1),0))<=0){
					printf("Send Error: %s (Errno:%d)\n",strerror(errno),errno);
					exit(0);
				}

				if((len=recv(sd,buff,sizeof(struct message_s),0))<=0){
					printf("receive error: %s (Errno:%d)\n", strerror(errno),errno);
				}

				struct message_s *be = malloc(sizeof(struct message_s));
				memcpy(be,buff,12);
				if(be->protocol[0] != 0xe3 || memcmp((char *)&be->protocol[1],"myftp",5) != 0){
					printf("Unknown protocol message recieved, program exit.\n");
					exit(0);
				}

				char* path = malloc(256);
				strcpy(path,token[1]);

				path[strlen(path)-1] = '\0';

				if((unsigned char )buff[6] == 0xA8){
					if((unsigned char )buff[7] == 1){
				//		be->length = be->length-13;
				//		printf("%d\n",be->length);

						FILE *fp = fopen(path, "wb+");

						if((len=recv(sd,buff,sizeof(struct message_s),0))<=0){
							printf("receive error: %s (Errno:%d)\n", strerror(errno),errno);
						}

						if((unsigned char )buff[6] != 0xAA){
							printf("Unexpected message.\n");
							continue;
						}
						memcpy(be,buff,12);
						be->length = be->length-12;
				//		printf("%d\n",be->length);

						if((len=recv(sd,buff,1024,0))<=0){
							printf("receive error: %s (Errno:%d)\n", strerror(errno),errno);
						}

						while(len >= 1024){
							fwrite(buff,1024,1,fp);
							be->length = be->length - 1024;
							if(be->length >= 1024){
								if((len=recv(sd,buff,1024,0))<=0){
									printf("receive error: %s (Errno:%d)\n", strerror(errno),errno);
								}
							} else {
								if((len=recv(sd,buff,be->length,0))<=0){
									printf("receive error: %s (Errno:%d)\n", strerror(errno),errno);
								}
							}
						}

						fwrite(buff,be->length,1,fp);
						fclose(fp);
						printf("Downloaded\n");

					} else if((unsigned char)buff[7] == 0){
					printf("File is not available in its repository!\n");
					}
				}
				
				free(be);

			} else {
				printf("Not logined yet!\n");
			}
		}

		if(strcmp(token[0],"put") == 0){

			if(token_num != 2){
				printf("Invaild command line. Usage: put <file name>\n");
				continue;
			}

			if(logined == true){
				int fd;           /* file descriptor for file to send */
				off_t offset = 0; /* file offset */
				struct stat stat_buf;      /* argument to fstat */
				int rc;                    /* holds return code of system calls */

				char *path = malloc(256);  
				strcpy(path,token[1]);
				path[strlen(path)-1] = '\0';

				fd = open(path, O_RDONLY);
				if (fd == -1) {
					fprintf(stderr, "unable to open '%s': %s\n", path, strerror(errno));
					continue;
				}
				fstat(fd, &stat_buf);

				if(S_ISREG(stat_buf.st_mode) == 0){
					fprintf(stderr, "Only regular file should be uploaded.\n");
					continue;
				}

				struct message_s PUT_REQUEST;
				PUT_REQUEST.protocol[0] = 0xe3;
				PUT_REQUEST.protocol[1] = 'm';
				PUT_REQUEST.protocol[2] = 'y';
				PUT_REQUEST.protocol[3] = 'f';
				PUT_REQUEST.protocol[4] = 't';
				PUT_REQUEST.protocol[5] = 'p';
				PUT_REQUEST.type = 0xA9;
				PUT_REQUEST.status = 0;
				PUT_REQUEST.length = 12+strlen(token[1])+1;
				if((len=send(sd,&PUT_REQUEST,sizeof(struct message_s),0))<=0){
					printf("Send Error: %s (Errno:%d)\n",strerror(errno),errno);
					exit(0);
				}
				if((len=send(sd,token[1],strlen(token[1]+1),0))<=0){
					printf("Send Error: %s (Errno:%d)\n",strerror(errno),errno);
					exit(0);
				}
				if((len=recv(sd,buff,sizeof(struct message_s),0))<=0){
					printf("receive error: %s (Errno:%d)\n", strerror(errno),errno);
				}

				struct message_s *be = malloc(sizeof(struct message_s));
				memcpy(be,buff,12);
				if(be->protocol[0] != 0xe3 || memcmp((char *)&be->protocol[1],"myftp",5) != 0){
					printf("Unknown protocol message recieved, program exit.\n");
					exit(0);
				}

				if(be->type == 0xAA){

					struct message_s FILE_DATA;
					FILE_DATA.protocol[0] = 0xe3;
					FILE_DATA.protocol[1] = 'm';
					FILE_DATA.protocol[2] = 'y';
					FILE_DATA.protocol[3] = 'f';
					FILE_DATA.protocol[4] = 't';
					FILE_DATA.protocol[5] = 'p';
					FILE_DATA.type = 0xFF;
					FILE_DATA.status = 0;
					FILE_DATA.length = 12+stat_buf.st_size;

					offset = 0;

					if((len=send(sd,&FILE_DATA,sizeof(struct message_s),0))<=0){
						printf("Send Error: %s (Errno:%d)\n",strerror(errno),errno);
						exit(0);
					}

					rc = sendfile(sd, fd, &offset, stat_buf.st_size);
					if (rc == -1) {
						fprintf(stderr, "error from sendfile: %s\n", strerror(errno));
						continue;
					}
					if (rc != stat_buf.st_size) {
						fprintf(stderr, "incomplete transfer from sendfile: %d of %d bytes\n",rc,(int)stat_buf.st_size);
						continue;
					}

					printf("File uploaded.\n");

				}
			} else {
				printf("Not logined yet!\n");
			}

		}

		if(strcmp(token[0],"exit") == 0){
			if(token_num != 1){
				printf("Invaild command line. Usage: exit\n");
				continue;
			}
			if(accepted == true){
				struct message_s EXIT_REQUEST;
				EXIT_REQUEST.protocol[0] = 0xe3;
				EXIT_REQUEST.protocol[1] = 'm';
				EXIT_REQUEST.protocol[2] = 'y';
				EXIT_REQUEST.protocol[3] = 'f';
				EXIT_REQUEST.protocol[4] = 't';
				EXIT_REQUEST.protocol[5] = 'p';
				EXIT_REQUEST.type = 0xAB;
				EXIT_REQUEST.status = 0;
				EXIT_REQUEST.length = 12;

				if((len=send(sd,&EXIT_REQUEST,sizeof(struct message_s),0))<=0){
					printf("Send Error: %s (Errno:%d)\n",strerror(errno),errno);
					exit(0);
				}
				if((len=recv(sd,buff,sizeof(struct message_s),0))<=0){
					printf("receive error: %s (Errno:%d)\n", strerror(errno),errno);
				}

				struct message_s *be = malloc(sizeof(struct message_s));
				memcpy(be,buff,12);
				if(be->protocol[0] != 0xe3 || memcmp((char *)&be->protocol[1],"myftp",5) != 0){
					printf("Unknown protocol message recieved, program exit.\n");
					exit(0);
				}

				if(be->type == 0xAC){
				printf("Thanks you.\n");
				return 0;
				}
			} else {
				printf("Thanks you.\n");
				return 0;
			}

		}
	}
	return 0;
}