#include <stdio.h>  /* for printf() and fprintf() */
#include <stdlib.h> /* for atoi() and exit()  */
#include <sys/socket.h> /* for socket(), bind(), sendto() and recvfrom() */
#include <unistd.h> /* for close() */
#include <string.h> /* for memset() */
#include <arpa/inet.h> /* for sockaddr_in and inet_ntoa() */
#include <sys/stat.h> /* for stat() */
#include <dirent.h> /* for opendir() and readdir() */
#include <errno.h>  /* for errno */
#include <time.h> /* for strftime() */
#include <sys/time.h> /* for timing */
#include <fcntl.h> /* for open() */
#include "method.h" /* for methods */

#define MAX 256

int sock; /* socket for listening */
int sock_connect_TCP; /* socket for TCP connection, data conncetion */
int sock_connect_TCP_listen; /* socket for TCP connection, data conncetion in passive mode */
struct sockaddr_in ftpServAddr; /* local address */
struct sockaddr_in ftpClntAddr; /* client address */
struct sockaddr_in dataClntAddr; /* client address */
struct sockaddr_in dataServAddr; /* local address */
char cliBuf[MAX]; /* buffer for client socket */
char serBuf[MAX]; /* buffer for server socket */
unsigned int cliAddrLen; /* length of client address */
unsigned short ftpServPort; /* server port */
int recvMsgSize; /* size of received message */
char ip[MAX]; /* ip of client, for data connection */
char portNum[MAX]; /* port number of client, for data connection */
int is_binary = 0; /* if it is transferred in binary mode */
int is_ascii = 1; /* if it is transferred in ASCII mode */

int main(int argc, char *argv[]){
    int sockNew; /* socket for sending */
    char username[MAX]; /* to store the username */
    char password[MAX]; /* to store the password */
    int auth = 0; /* authority, 0 - not log in, 
                   1 - normal user, can not make directory, delete, rename, 
                   2 - super user, can do all operations */
    if (argc != 2){
        printf("Usage: %s <TCP SERVER PORT>\n", argv[0]);
        exit(0);
    } /* judge whether the input is legal */
    
    bzero(cliBuf,MAX);
    ftpServPort = atoi(argv[1]); /* first arg: local port, usually 21 */
    
    /* create socket for sending/receiving datagrams */
    if( (sock = socket(PF_INET, SOCK_STREAM, 0)) < 0){
        printf("socket() failed.\n");
    }

    /* construct local address structure */
    memset(&ftpServAddr, 0, sizeof(ftpServAddr));
    ftpServAddr.sin_family = AF_INET;
    ftpServAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    ftpServAddr.sin_port = htons(ftpServPort);

    /* bind to the local address */
    if( bind(sock, (struct sockaddr *) &ftpServAddr, sizeof(ftpServAddr)) < 0 ){
        printf("bind() failed.\n");
        exit(0);
    }

    /* place a socket in passive mode and make it ready to accept incoming connections */
    if( listen(sock,10) < 0 ){
        printf("listen() failed.\n");
        exit(0);
    }

    printf("----------------ftp server starts running.----------------\n");

    for(;;){ /* run forever */
        /* set the size of the in-out parameter */
        cliAddrLen = sizeof(ftpClntAddr);
        
        /* block until accept a connection and create a new socket */
        sockNew = accept(sock, (struct sockaddr *) &ftpClntAddr, &cliAddrLen);
        if( sockNew < 0 ){
            printf("accept() failed.\n");
            exit(0);
        }
        if(write(sockNew,"220 (IAFTP 1.0.2)\r\n", strlen("220 (IAFTP 1.0.2)\r\n")) < 0){
            printf("write() failed.\n");
            exit(0);
        }
        /* print the information of client's ip address */
        printf("Client IP: %s, TCP port number: %d\n",inet_ntoa(ftpClntAddr.sin_addr), ftpClntAddr.sin_port);
        bzero(cliBuf,MAX); /* clear the client buffer */
        bzero(username,MAX); /* clear the username buffer */
        bzero(password,MAX); /* clear the password buffer */

        
        /* ------------------------------------------------------------------ */
        /* now the socket is set ok */
        /* below are modules of different function */

        while(1){
            /* read the message from socket */
            if( read(sockNew, cliBuf, MAX) < 0){
                printf("read() failed.\n");
                exit(0);
            }

            /* 0. Log in function */
            if(strncmp(cliBuf,"USER",4) == 0){ /* 此时缓存区的内容为 USER username\r\n */
                strncpy(username,cliBuf+5,strlen(cliBuf)-7); /* 提取出username, 忽略一开始的 USER 和最后的换行 */
                printf("The username is %s\n", username); /* print the received username */
                write(sockNew,"331 Please enter password.\r\n", strlen("331 Please enter password.\r\n"));
                bzero(cliBuf,MAX); /* clear the client buffer */

                /* read the message from socket into cliBuf, second is password */
                if( read(sockNew, cliBuf, MAX) < 0){
                    printf("read() failed.\n");
                    exit(0);
                }
                strncpy(password,cliBuf+5,strlen(cliBuf)-7); /* 提取出password, 忽略一开始的 PASS 和最后的换行 */
                printf("The password is %s\n", password); /* print the received username */

                if(strncmp(cliBuf,"PASS",4) == 0){ /* 此时缓存区的内容为 PASS password\r\n */
                    if(strcmp(username,"student") == 0 && strcmp(password,"111111") == 0){ /* 验证账号密码是否正确, 普通用户 */
                        write(sockNew,"230 Log in successfully.\r\n", strlen("230 Log in successfully.\r\n"));
                        bzero(cliBuf,MAX); /* clear the client buffer */
                        auth = 1;
                        printf("authority level: 1, normal user\n");
                        printf("--Action-- Log in successfully.\n");
                    } else if (strcmp(username,"sqj") == 0 && strcmp(password,"111111") == 0){ /* 验证账号密码是否正确, 高级用户 */
                        write(sockNew,"230 Log in successfully.\r\n", strlen("230 Log in successfully.\r\n"));
                        bzero(cliBuf,MAX); /* clear the client buffer */
                        auth = 2;
                        printf("authority level: 2, super user\n");
                        printf("--Action-- Log in successfully.\n");
                    } else { /* 账号或密码错误, 登陆失败 */
                        write(sockNew,"530 Log in incorrect.\r\n", strlen("530 Log in incorrect.\r\n"));
                        bzero(cliBuf,MAX); /* clear the client buffer */
                        auth = 0;
                        printf("--Action-- User log in failed\n");
                        bzero(username,MAX);
                        bzero(password,MAX);
                        continue;
                    }
                }

                /* read the message from socket into cliBuf, third is system type */
                if( read(sockNew, cliBuf, MAX) < 0){
                    printf("read() failed.\n");
                    exit(0);
                }
                if(strncmp(cliBuf,"SYST",4) == 0){ /* 此时缓存区的内容为 SYST\r\n */
                    if(auth == 0){
                        write(sockNew,"530 Please log in with USER and PASS.\r\n", strlen("530 Please log in with USER and PASS.\r\n"));
                    }else{
                        write(sockNew,"215 Linux \r\n", strlen("215 Linux \r\n"));
                    }
                    bzero(cliBuf,MAX); /* clear the client buffer */
                }
            
            
            }

            /* 1. Quit function */
            if(strncmp(cliBuf,"QUIT",4) == 0){ /* 此时缓存区的内容为 QUIT\r\n */
                write(sockNew,"221 Goodbye.\r\n", strlen("221 Goodbye.\r\n"));
                printf("--Action-- User: %s log out.\n",username);
                bzero(cliBuf,MAX); /* clear the client buffer */
                bzero(username,MAX); /* clear the username buffer */
                bzero(password,MAX); /* clear the password buffer */
                break;
            }

            if(auth == 0){ /* if not log in, block all other commands */
                write(sockNew,"530 Please log in with USER and PASS.\r\n", strlen("530 Please log in with USER and PASS.\r\n"));
                bzero(cliBuf,MAX); 
                bzero(username,MAX); 
                bzero(password,MAX); 
            }

            /* 2. PWD function */
            if(strncmp(cliBuf,"PWD",3) == 0){ /* 此时缓存区的内容为 PWD\r\n */
                cmd_pwd(sockNew);
                bzero(cliBuf,MAX); /* clear the client buffer */
                printf("--Action-- PWD, show present working directory.\n");
            }

            /* 3. CWD function */
            if(strncmp(cliBuf,"CWD",3) == 0){ /* 此时缓存区的内容为 CWD destination directory\r\n */
                char desDir[MAX];
                bzero(desDir,MAX); /* clear the desDir */
                strncpy(desDir,cliBuf+4,strlen(cliBuf)-6); /* 提取出想要到达的目录, 忽略一开始的 CWD 和最后的换行 */
                cmd_cwd(sockNew, desDir);
                bzero(cliBuf,MAX); /* clear the client buffer */
            }

             /* 4. LIST, RETR, STOR function, in active mode */
            if(strncmp(cliBuf,"PORT",4) == 0){ /* in list command, client sends a PORT command first */
                read_ip_port();
                if(write(sockNew,"200 PORT command successful. Now using Active Mode.\r\n", strlen("200 PORT command successful. Now using Active Mode.\r\n")) < 0){
                    printf("write() failed. Code: 200\n");
                }
                bzero(cliBuf,MAX);
                /* read the message from socket */
                if( read(sockNew, cliBuf, MAX) < 0){
                    printf("read() failed.\n");
                    exit(0);
                }
                if(strncmp(cliBuf,"LIST",4) == 0){
                    data_con_act(); /* create data connection */
                    cmd_list(sockNew); /* call cmd_list() function to send ls information */
                }else if(strncmp(cliBuf,"RETR",4) == 0){
                    if(auth == 2){
                        data_con_act(); /* create data connection */
                        cmd_retr(sockNew,-1);
                    }
                    if(auth == 1){
                        data_con_act(); /* create data connection */
                        cmd_retr(sockNew,30);
                    }
                    if(auth == 0){
                        /* 普通用户没有权限，无法进行MKD操作 */
                        write(sockNew, "530 You have no authority.\r\n", strlen("530 You have no authority.\r\n"));
                    }
                }else if(strncmp(cliBuf,"STOR",4) == 0){
                    if(auth == 2){
                        data_con_act(); /* create data connection */
                        cmd_stor(sockNew,-1);
                    }
                    if(auth == 1){
                        data_con_act(); /* create data connection */
                        cmd_stor(sockNew,1);
                    }
                    if(auth == 0){
                    /* 普通用户没有权限，无法进行MKD操作 */
                    write(sockNew, "530 You have no authority.\r\n", strlen("530 You have no authority.\r\n"));
                    }
                }
                
                bzero(cliBuf,MAX); /* clear the client buffer */
                bzero(ip,MAX); /* clear ip */
                bzero(portNum,MAX); /* clear portNum */
            }

            /* 5. LIST, RETR, STOR function, in passive mode */
            if(strncmp(cliBuf,"PASV",4) == 0){ /* in list command, client sends a PORT command first */
                if(write(sockNew,"227 Entering Passive Mode (127,0,0,1,200,100).\r\n", strlen("227 Entering Passive Mode (127,0,0,1,200,100).\r\n")) < 0){
                    printf("write() failed. Code: 200\n");
                }
                bzero(cliBuf,MAX);
                data_con_pasv(); /* create data connection */
                /* read the message from socket */
                if( read(sockNew, cliBuf, MAX) < 0){
                    printf("read() failed.\n");
                    exit(0);
                }
                if(strncmp(cliBuf,"LIST",4) == 0){
                    cmd_list(sockNew); /* call cmd_list() function to send ls information */
                }else if(strncmp(cliBuf,"RETR",4) == 0){
                    if(auth == 2){
                        cmd_retr(sockNew,-1);
                    }
                    if(auth == 1){
                        cmd_retr(sockNew,30);
                    }
                    if(auth == 0){
                        /* 未登录不能下载 */
                        write(sockNew, "530 You have no authority.\r\n", strlen("530 You have no authority.\r\n"));
                        close(sock_connect_TCP);
                    }
                }else if(strncmp(cliBuf,"STOR",4) == 0){
                    if(auth == 2){
                        cmd_stor(sockNew,-1);
                    }
                    if(auth == 1){
                        cmd_stor(sockNew,1);
                    }
                    if(auth == 0){
                        /* 未登录不能下载 */
                        write(sockNew, "530 You have no authority.\r\n", strlen("530 You have no authority.\r\n"));
                        close(sock_connect_TCP);
                    }    
                }
                
                close(sock_connect_TCP_listen);
                bzero(cliBuf,MAX); /* clear the client buffer */
                bzero(ip,MAX); /* clear ip */
                bzero(portNum,MAX); /* clear portNum */
            }

            /* 6. MKD function */
            if(strncmp(cliBuf,"MKD",3) == 0){ /* 此时缓存区的内容为 MKD directory name\r\n */
                if(auth == 2){
                    char dir_name[MAX];
                    bzero(dir_name,MAX); /* clear the dir_name */
                    strncpy(dir_name,cliBuf+4,strlen(cliBuf)-6); /* 提取出想要创建的目录名, 忽略一开始的 MKD 和最后的换行 */
                    cmd_mkd(sockNew,dir_name);
                }else{
                    /* 普通用户没有权限，无法进行MKD操作 */
                    write(sockNew, "530 You have no authority.\r\n", strlen("530 You have no authority.\r\n"));
                }
                bzero(cliBuf,MAX); /* clear the client buffer */
            }

            /* 7. DELE function */
            if(strncmp(cliBuf,"DELE",4) == 0){ /* 此时缓存区的内容为 DELE file name\r\n */
                if(auth == 2){
                    char file_name[MAX];
                    bzero(file_name,MAX); /* clear the file_name */
                    strncpy(file_name,cliBuf+5,strlen(cliBuf)-7); /* 提取出想要删除的文件名, 忽略一开始的 DELE 和最后的换行 */
                    cmd_dele(sockNew,file_name);
                }else{
                    /* 普通用户没有权限，无法进行MKD操作 */
                    write(sockNew, "530 You have no authority.\r\n", strlen("530 You have no authority.\r\n"));
                }
                bzero(cliBuf,MAX); /* clear the client buffer */
            }

            /* 8. RNFR function */
            if(strncmp(cliBuf,"RNFR",4) == 0){ /* 此时缓存区的内容为 DELE file name\r\n */
                if(auth == 2){
                    char RNFR[MAX];
                    bzero(RNFR,MAX); /* clear the RNFR */
                    strncpy(RNFR,cliBuf+5,strlen(cliBuf)-7); /* 提取出想要重命名的文件名, 忽略一开始的 RNFR 和最后的换行 */
                    cmd_rnfr(sockNew,RNFR);
                }else{
                    /* 普通用户没有权限，无法进行MKD操作 */
                    write(sockNew, "530 You have no authority.\r\n", strlen("530 You have no authority.\r\n"));
                }
                bzero(cliBuf,MAX); /* clear the client buffer */
            }

            /* 9. TYPE function */
            if(strncmp(cliBuf,"TYPE",4) == 0){
                char type[MAX];
                bzero(type,MAX); /* clear the RNFR */
                strncpy(type,cliBuf+5,strlen(cliBuf)-7); /* 提取出想要重命名的文件名, 忽略一开始的 RNFR 和最后的换行 */
                if(strcmp(type,"I") == 0){
                    is_binary = 1;
                    is_ascii = 0;
                    write(sockNew, "200 Switching to Binary mode.\r\n", strlen("200 Switching to Binary mode.\r\n"));
                }else if (strcmp(type,"A") == 0){
                    is_ascii = 1;
                    is_binary = 0;
                    write(sockNew, "200 Switching to ASCII mode.\r\n", strlen("200 Switching to ASCII mode.\r\n"));
                }
                
            }
        }
        
    }

    return 0;
}

/* function for PWD */
void cmd_pwd(int socket){
    char dir[MAX]; /* to store the current working directory */
    bzero(dir,MAX);
    if(getcwd(dir,MAX) == NULL){ /* get the current working directory and store it into dir */
        printf("getcwd() failed.\n");
        exit(0);
    }
    sprintf(cliBuf,"257 \"%s\"\r\n", dir); /* write the cwd into cliBuf */
    if(write(socket,cliBuf,strlen(cliBuf)) < 0){ /* send back message */
        printf("write() failed.\n");
        exit(0);
    }
}

/* function for CWD */
void cmd_cwd(int socket, char * destination){
    if(chdir(destination) < 0){ /* change working directory */
        printf("--Action-- CWD, change directory failed.\n");
        write(socket,"550 Failed to change directory.\r\n",strlen("550 Failed to change directory.\r\n"));
        return;
    }
    if(write(socket,"250 Directory successfully changed.\r\n",strlen("250 Directory successfully changed.\r\n")) < 0){ /* send back message */
        printf("write() failed.\n");
        exit(0);
    }
    printf("--Action-- CWD, directory changed.\n");
}

/* read the ip address and port number from socket buffer, used in active mode */
void read_ip_port(void){
    int port[2] = {0,0};
    int num = 0;
    char address[MAX];
    char *token;
    int socket_data_con;
    bzero(address,MAX); /* clear address buffer */
    strncpy(address,cliBuf+5,strlen(cliBuf)-7); /* 提取出ip和port, 忽略一开始的 PORT 和最后的换行 */
    bzero(ip,MAX); /* clear ip buffer */
    /* 提取ip和port, 存入数组 */
    token = strtok(address,","); 
    while(token != NULL){
        num++;
        if(num < 4){
            strcat(ip,token);
            strcat(ip,".");
        } else if(num == 4){
            strcat(ip,token);
            strcat(ip,"\0");
        } else if(num >= 5){
            port[num-5] = atoi(token);
        }
        token = strtok(NULL,",");
    }

    bzero(portNum,MAX); /* clear ip buffer */
    sprintf(portNum,"%d",port[0]*256+port[1]); /* 计算port, 转换成字符串 */
}


/* create the socket for data connection in active mode */
void create_sock_data_con_act(void) {/* 配置sock_connect_TCP，用来建立data connection */
    unsigned short dataServPort = 20; /* server port */

    /* construct server address structure */
    memset(&dataServAddr, 0, sizeof(dataServAddr));
    dataServAddr.sin_family = AF_INET;
    dataServAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    dataServAddr.sin_port = htons(dataServPort);

    if( (sock_connect_TCP = socket(PF_INET, SOCK_STREAM, 0)) < 0){
        printf("socket() failed.\n");
    }

    /* 由于active mode需要用到指定的端口号20，如果按照默认配置，在一次data connection结束后，20号端口会处于
       TIME_WAIT 状态，在几分钟之内，无法再次被用来建立data connection，因此需要用setsockopt()函数来配置socket，
       使得该端口号在被释放后能立刻被重新使用 */
    int iSockOptVal = 1;
    if (setsockopt(sock_connect_TCP, SOL_SOCKET, SO_REUSEADDR, &iSockOptVal, sizeof(iSockOptVal)) == -1) {
        perror("setsockopt fail");
        close(sock_connect_TCP);
        exit(EXIT_FAILURE);
    }

    /* 将socket绑定到本地ip地址和20号端口 */
    if( bind(sock_connect_TCP, (struct sockaddr *) &dataServAddr, sizeof(dataServAddr)) < 0 ){
        printf("bind() failed.\n");
        exit(0);
    }

}

/* function for data connection, active mode */
void data_con_act(void){
    create_sock_data_con_act(); /* create socket for data connection in active mode */
    printf("--Action-- Start open data connection.\n");
     
    /* construct client address structure */
    memset(&dataClntAddr, 0, sizeof(dataClntAddr));
    dataClntAddr.sin_family = AF_INET;
    dataClntAddr.sin_addr.s_addr = inet_addr(ip);
    dataClntAddr.sin_port = htons(atoi(portNum));
    
    /* connect to client */
    extern int errno;
    if ( (connect(sock_connect_TCP,(struct sockaddr *) &dataClntAddr, sizeof(dataClntAddr))) < 0){
        printf("connect() failed.\n");
        printf("errno = %d\n",errno);
        exit(0);
    }
    printf("--Action-- Data connection opened to: ip - %s, port - %s\n", ip, portNum);
}

/* create the socket for data connection in passive mode */
void create_sock_data_con_pasv(void) {/* 配置sock_connect_TCP，用来建立data connection */
    unsigned short dataServPort = 51300; /* server port */

    /* construct server address structure */
    memset(&dataServAddr, 0, sizeof(dataServAddr));
    dataServAddr.sin_family = AF_INET;
    dataServAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    dataServAddr.sin_port = htons(dataServPort);

    if( (sock_connect_TCP_listen = socket(PF_INET, SOCK_STREAM, 0)) < 0){
        printf("socket() failed.\n");
    }

    /* 由于active mode需要用到指定的端口号51300，如果按照默认配置，在一次data connection结束后，51300号端口会处于
       TIME_WAIT 状态，在几分钟之内，无法再次被用来建立data connection，因此需要用setsockopt()函数来配置socket，
       使得该端口号在被释放后能立刻被重新使用 */
    int iSockOptVal = 1;
    if (setsockopt(sock_connect_TCP_listen, SOL_SOCKET, SO_REUSEADDR, &iSockOptVal, sizeof(iSockOptVal)) == -1) {
        perror("setsockopt fail");
        close(sock_connect_TCP_listen);
        exit(EXIT_FAILURE);
    }

    /* 将socket绑定到本地ip地址和对应端口 */
    if( bind(sock_connect_TCP_listen, (struct sockaddr *) &dataServAddr, sizeof(dataServAddr)) < 0 ){
        printf("bind() failed.\n");
        exit(0);
    }

    /* place a socket in passive mode and make it ready to accept incoming connections */
    if( listen(sock_connect_TCP_listen,10) < 0 ){
        printf("listen() failed.\n");
        exit(0);
    }

}

/* function for data connection, passive mode */
void data_con_pasv(void){
    create_sock_data_con_pasv(); /* create socket for data connection in passive mode */
    printf("--Action-- Data connection in passive mode, start listening.\n");
    unsigned int dataClntAddrLen = sizeof(dataClntAddr);

    /* connect to client */
    sock_connect_TCP = accept(sock_connect_TCP_listen, (struct sockaddr *) &dataClntAddr, &dataClntAddrLen);
    if( sock_connect_TCP < 0 ){
        printf("accept() failed.\n");
        exit(0);
    }
    
    printf("--Action-- Data connection opened to: ip - %s, port - %d\n", inet_ntoa(dataClntAddr.sin_addr), ntohs(dataClntAddr.sin_port));
}



/* function for LIST */
void cmd_list(int socket_input){
        bzero(cliBuf,MAX); /* clear the client buffer */

        /* send 150 message */
        if(write(socket_input,"150 Here conmes the directory listing.\r\n",strlen("150 Here conmes the directory listing.\r\n")) < 0){ /* send back message */
            printf("write() failed. Code: 150\n");
            exit(0);
        }
        
        /* read the file name in current directory */
        DIR * mydir =NULL;
        struct dirent *myitem = NULL; /* structure for files */
	    struct stat sbuf; /* structure for file statue */
        char content[MAX] ;
        bzero(content, MAX);
        if((mydir=opendir(".")) == NULL){
            printf("OpenDir Error!\n");
            exit(0);
        }
        while((myitem = readdir(mydir)) != NULL)
        {
            if (lstat(myitem->d_name, &sbuf) < 0){ /* get information of files */
			    continue;
		    }
            if (myitem->d_name[0] == '.'){ /* ignore "." and ".." */
                continue;
            }
			
            const char *perms = statbuf_get_perms(&sbuf); /* get the permission information */

            /* write the information of files into content */
			int off = 0;
			off += sprintf(content, "%s ", perms); /* permission */
			off += sprintf(content + off, " %3d %-8d %-8d ", sbuf.st_nlink, sbuf.st_uid, sbuf.st_gid); /* number of link, user id, group id */
			off += sprintf(content + off, "%8lu ", (unsigned long)sbuf.st_size); /* size of file */

			const char *datebuf = statbuf_get_date(&sbuf); /* get the time information */
			off += sprintf(content + off, "%s ", datebuf); /* write the time information into content */

		    off += sprintf(content + off, "%s\r\n", myitem->d_name); /* write the file name into content */

            write(sock_connect_TCP, content, strlen(content)); /* send the message */
        }

        closedir(mydir); /* close mydir */
        close(sock_connect_TCP); /* close socket for data connection */
        printf("--Action-- Data connection closed.\n");

        /* send 226 message */
        if(write(socket_input,"226 Directory send ok.\r\n",strlen("226 Directory send ok.\r\n")) < 0){ /* send back message */
            printf("write() failed.\n");
            exit(0);
        }
        printf("--Action-- LIST, list info transferred successfully.\n");
    
}   
/* get the permission information and format it */
const char* statbuf_get_perms(struct stat *sbuf)
{
	static char perms[] = "----------";
	perms[0] = '?';

	mode_t mode = sbuf->st_mode;
	switch (mode & S_IFMT) /* file types */
	{
	case S_IFREG:
		perms[0] = '-'; /* normal file */
		break;
	case S_IFDIR:
		perms[0] = 'd'; /* directory */
		break;
	case S_IFLNK:
		perms[0] = 'l'; /* link */
		break;
	case S_IFIFO: 
		perms[0] = 'p'; /* fifo */
		break;
	case S_IFSOCK:
		perms[0] = 's'; /* socket */
		break;
	case S_IFCHR:
		perms[0] = 'c'; /* character device */
		break;
	case S_IFBLK:
		perms[0] = 'b'; /* block device */
		break;
	}

	if (mode & S_IRUSR) /* file permissions */
	{
		perms[1] = 'r'; /* readable for owner */
	}
	if (mode & S_IWUSR)
	{
		perms[2] = 'w'; /* writable for owner */
	}
	if (mode & S_IXUSR)
	{
		perms[3] = 'x'; /* executable for owner */
	}
	if (mode & S_IRGRP)
	{
		perms[4] = 'r'; /* readable for user group */
	}
	if (mode & S_IWGRP)
	{
		perms[5] = 'w'; /* writable for user group */
	}
	if (mode & S_IXGRP)
	{
		perms[6] = 'x'; /* executable for user group */
	}
	if (mode & S_IROTH)
	{
		perms[7] = 'r'; /* readable for other user */
	}
	if (mode & S_IWOTH)
	{
		perms[8] = 'w'; /* writable for other user */
	}
	if (mode & S_IXOTH)
	{
		perms[9] = 'x'; /* executable for other user */
	}
	if (mode & S_ISUID) /* user id, if the file is executable for owner, show in lower case, otherwise, upper case */
	{
		perms[3] = (perms[3] == 'x') ? 's' : 'S';
	}
	if (mode & S_ISGID) /* group id, similar to user id */
	{
		perms[6] = (perms[6] == 'x') ? 's' : 'S';
	}
	if (mode & S_ISVTX) /* sticky, similar to user id, if user has permission of writting to a directory, he can
                           delete files in the directory，the function of sticky is: the sticky is setted to 
                           prevent users to delete files that don't belong to them */
	{
		perms[9] = (perms[9] == 'x') ? 't' : 'T';
	}

	return perms;
}

/* get time information and format it */
const char* statbuf_get_date(struct stat *sbuf)
{
	static char datebuf[64] = {0}; /* buffer for date */
	const char *p_date_format = "%b %e %H:%M"; /* time format, month date hour:minute */
	struct timeval tv; /* struct for current time */
	gettimeofday(&tv, NULL); /* get current time */
	time_t local_time = tv.tv_sec;
	if (sbuf->st_mtime > local_time || (local_time - sbuf->st_mtime) > 60*60*24*182) /* if time of last change is too long ago, change the time format */
	{
		p_date_format = "%b %e  %Y"; /* month date year */
	}

	strftime(datebuf, sizeof(datebuf), p_date_format, gmtime(&sbuf->st_mtime)); /* format the time of last change and write into date buffer */

	return datebuf;
}

/* function for MKD */
void cmd_mkd(int socket_input, char * dir_name){
    char dir_current[MAX]; /* to store the current working directory */
    bzero(dir_current,MAX);
    if(getcwd(dir_current,MAX) == NULL){ /* get the current working directory and store it into dir */
        printf("getcwd() failed.\n");
        exit(0);
    }
    
    strcat(dir_current,"/");
    strcat(dir_current,dir_name);
    if(mkdir(dir_current,S_IRWXU) < 0){
        printf("mkdir() failed.\n");
        exit(0);
    }
    printf("--Action-- MKD, directory made successfully.\n");

    sprintf(cliBuf,"257 \"%s\" created.\r\n", dir_current);
    /* send 257 message */
    if(write(socket_input, cliBuf, strlen(cliBuf)) < 0){ /* send back message */
        printf("write() failed.\n");
        exit(0);
    }
}

/* function for DELE */
void cmd_dele(int socket_input, char * file_name){
    if(remove(file_name) < 0){/* remove the file */
        printf("--Action-- DELE failed, no such file.\n");
        write(socket_input,"550 Delete operation failed.\r\n", strlen("550 Delete operation failed.\r\n"));
        return;
    }

    printf("--Action-- DELE, delete %s successfully.\n",file_name);
    /* send 250 message */
    if(write(socket_input,"250 Delete operation successful.\r\n", strlen("250 Delete operation successful.\r\n")) < 0){
        printf("write() failed.\n");
        exit(0);
    }
}

/* function for RNFR */
void cmd_rnfr(int socket_input, char * file_name_original){
    /* send 350 message */
    if(write(socket_input,"350 Ready for RNTO.\r\n", strlen("350 Ready for RNTO.\r\n")) < 0){ 
        printf("write() failed.\n");
        exit(0);
    }
    printf("--Action-- RNFR, start renaming file, original file name: %s\n", file_name_original);
    bzero(cliBuf,MAX);

    /* read the RNTO message from socket */
    if( read(socket_input, cliBuf, MAX) < 0){
        printf("read() failed.\n");
        exit(0);
    }
    /* receive RNTO message */
    if(strncmp(cliBuf,"RNTO",4) == 0){
        char RNTO[MAX];
        bzero(RNTO,MAX); /* clear the RNTO */
        strncpy(RNTO,cliBuf+5,strlen(cliBuf)-7); /* 提取出重命名后的文件名, 忽略一开始的 RNTO 和最后的换行 */
        cmd_rnto(socket_input, file_name_original, RNTO);
    }
}
    
/* function for RNTO */
void cmd_rnto(int socket_input,char * file_name_original, char * file_name_present){
    /* rename the file */
    if(rename(file_name_original,file_name_present) < 0){
        printf("rename failed.\n");
        write(socket_input,"550 RNTO command failed.\r\n",strlen("550 RNTO command failed.\r\n"));
        exit(0);
    }

    /* send 250 message */
    if(write(socket_input,"250 Rename successful.\r\n", strlen("250 Rename successful.\r\n")) < 0){
        printf("write() failed.\n");
        exit(0);
    }
    printf("--Action-- RNTO, finish renaming file, present file name: %s\n", file_name_present);
}

void cmd_retr(int socket_input, int limit_speed){
    char file_name[MAX];
    bzero(file_name,MAX); /* clear the RNFR */
    strncpy(file_name,cliBuf+5,strlen(cliBuf)-7); /* 提取出想要下载的文件名, 忽略一开始的 RETR 和最后的换行 */
    bzero(cliBuf,MAX);

    /* open the file */
    int fd; /* file descriptor */
    int total_bytes = 0; /* total number of file */
    char buffer[MAX]; /* buffer for file content */
    bzero(buffer, MAX);
    char socket_content[MAX]; /* buffer for content of original socket */
    bzero(socket_content, MAX);

    printf("--Action-- RETR, 1. Open file: [ %s ]\n",file_name);
    if((fd=open(file_name, O_RDONLY)) < 0){
        printf("Open file Error!\n");
        close(sock_connect_TCP);
        write(socket_input, "550 Transfer failed.\n", strlen("550 Transfer failed.\n")); /* send 226 message */
        return ;
    }

    printf("--Action-- RETR, 2. Start transfering.\n");
    sprintf(socket_content, "150 Opening BINARY mode data connection for %s .\r\n", file_name); 
    write(socket_input, socket_content, strlen(socket_content)); /* send 150 message */

    int temp=0; /* store number of byte temporarily */
    struct timeval starttime,endtime; /* struct for timing */
    gettimeofday(&starttime,0); /* start timing */

    while((temp = read(fd, buffer, MAX)) > 0){
        if(write(sock_connect_TCP, buffer, temp) < 0){ /* send file */
            printf("write() failer.\n");
            close(fd);
            exit(1);
        }
        total_bytes += temp;
    }

    unsigned int limit_time = 0;
    if(limit_speed == -1){
        limit_time = 0;
    }else{
        limit_time = total_bytes / limit_speed;
    }
    usleep(limit_time*1000);

    gettimeofday(&endtime,0); /* end timing */
    double timeuse = 1000000*(endtime.tv_sec - starttime.tv_sec) + endtime.tv_usec - starttime.tv_usec;
    timeuse /=1000; /* 除以1000则进行毫秒计时，如果除以1000000则进行秒级别计时，如果除以1则进行微妙级别计时 */
    double speed = total_bytes/timeuse;

    close(fd);
    close(sock_connect_TCP);

    printf("--Action-- RETR, 3. Finish transfering. [ %d ] bytes sent in [ %.4lf ] ms, speed: [ %.2lf kB/s] \n", total_bytes, timeuse, speed);
    printf("--Action-- Data connection closed.\n");
    write(socket_input, "226 Transfer complete.\n", strlen("226 Transfer complete.\n")); /* send 226 message */
}

void cmd_stor(int socket_input, int is_limitted){
    char file_name[MAX];
    bzero(file_name,MAX); /* clear the RNFR */
    strncpy(file_name,cliBuf+5,strlen(cliBuf)-7); /* 提取出想要下载的文件名, 忽略一开始的 RETR 和最后的换行 */
    bzero(cliBuf,MAX);

    /* open the file */
    int fd; /* file descriptor */
    int total_bytes = 0; /* total number of file */
    char buffer[MAX]; /* buffer for file content */
    bzero(buffer, MAX);
    char socket_content[MAX]; /* buffer for content of original socket */
    bzero(socket_content, MAX);

    printf("--Action-- STOR, 1. Open file: [ %s ]\n",file_name);
    if((fd=open(file_name, O_WRONLY|O_CREAT|O_TRUNC, 0644)) < 0){
        printf("Open file Error!\n");
        return ;
    }
    write(socket_input, "150 Ok to send data.\r\n", strlen("150 Ok to send data.\r\n")); /* send 150 message */
    
    int temp = 0; /* store number of byte temporarily */
    printf("--Action-- STOR, 2. Start receiving.\n");
    
    struct timeval starttime,endtime; /* struct for timing */
    gettimeofday(&starttime,0); /* start timing */

    unsigned int limit_time;
    if(is_limitted != -1){
        limit_time = 1000000;
    }else{
        limit_time = 0;
    }
    usleep(limit_time);

    while((temp=read(sock_connect_TCP, buffer, MAX)) > 0){
        if(write(fd, buffer, temp) < 0){ /* send file */
            printf("write() failed.\n");
            close(fd);
            exit(1);
        }
        total_bytes +=temp;
        
    }
    
    gettimeofday(&endtime,0); /* end timing */
    double timeuse = 1000000*(endtime.tv_sec - starttime.tv_sec) + endtime.tv_usec - starttime.tv_usec;
    timeuse /=1000; /* 除以1000则进行毫秒计时，如果除以1000000则进行秒级别计时，如果除以1则进行微妙级别计时 */
    double speed = total_bytes/timeuse;

    close(fd);
    close(sock_connect_TCP);

    printf("--Action-- STOR, 3. Finish transfering. [ %d ] bytes received in [ %.4lf ] ms, speed: [ %.2lf kB/s] \n", total_bytes, timeuse, speed);
    printf("--Action-- Data connection closed.\n");
    write(socket_input, "226 Transfer complete.\r\n", strlen("226 Transfer complete.\r\n")); /* send 226 message */
}