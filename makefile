#makefile
cc = gcc

ftpServer : ftpServer.o 
   $(cc)  ftpServer.o -o ftpServer 

ftpServer.o : ftpServer.c method.h
   $(cc) -c ftpServer.c 
   
clean :
   rm ftpServer *.o